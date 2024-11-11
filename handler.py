import boto3
import gzip
import urllib.request
import os
from io import BytesIO
from datetime import datetime, timedelta
from botocore.awsrequest import AWSRequest
import botocore.auth as auth

def main(event, context):
    # 定数
    S3_BUCKET = os.getenv('S3_BUCKET')
    CLUSTERS  = os.getenv('CLUSTERS').split(',')

    # クライアント
    rds_client = boto3.client('rds')
    s3_client  = boto3.client('s3')

    # セッション情報
    session     = boto3.session.Session()
    region      = session.region_name
    credentials = session.get_credentials()

    # SigV4署名
    sigv4auth = auth.SigV4Auth(credentials, 'rds', region)

    # 最終更新時刻が2時間15分前から1時間前までのログを処理対象とする
    now           = datetime.now()
    two_hours_ago = int((now - timedelta(hours=2, minutes=15)).timestamp() * 1000)
    one_hour_ago  = int((now - timedelta(hours=1)).timestamp() * 1000)

    # クラスター一覧を取得し、ループ処理
    clusters = rds_client.describe_db_clusters(
        Filters=[{
            'Name':   'db-cluster-id',
            'Values': CLUSTERS
        }]
    )
    for cluster in clusters['DBClusters']:
        cluster_name = cluster['DBClusterIdentifier']

        print(f"Processing cluster: {cluster_name}")

        # インスタンス一覧を取得し、ループ処理
        instances = cluster['DBClusterMembers']
        for instance in instances:
            instance_name = instance['DBInstanceIdentifier']
            print(f"Processing instance: {instance_name}")

            # 対象のログファイル一覧を取得
            download_log_file_names = []
            marker = None
            while True:
                params = {
                    'DBInstanceIdentifier': instance_name,
                    'FileLastWritten':      two_hours_ago,
                    'MaxRecords':           256
                }
                if marker:
                    params['Marker'] = marker

                logs = rds_client.describe_db_log_files(**params)

                download_log_file_names.extend([
                    log['LogFileName'] for log in logs['DescribeDBLogFiles']
                    if two_hours_ago <= log['LastWritten'] < one_hour_ago and log['LogFileName'].startswith('audit/')
                ])

                marker = logs.get('Marker')
                if not marker:
                    break

            # ログファイルをループ処理
            for log_file_name in download_log_file_names:
                print(f"Processing log file: {log_file_name}")

                # S3オブジェクトキーを生成
                timestamp  = datetime.strptime(log_file_name.split('.')[3], '%Y-%m-%d-%H-%M')
                object_key = f"{cluster_name}/audit/{timestamp.year}/{timestamp.month:02}/{timestamp.day:02}/{timestamp.hour:02}/{instance_name}/{log_file_name.split('/')[-1]}.gz"

                # S3で同一のファイル名が存在するか確認
                try:
                    s3_client.head_object(Bucket=S3_BUCKET, Key=object_key)
                    print(f"File already exists in S3: {object_key}. Skipped.")
                    continue  # ファイルが存在する場合は、処理をスキップ
                except s3_client.exceptions.ClientError as e:
                    pass # ファイルが存在しない場合は、処理を続行

                # 署名付きURLを生成
                host   = f"rds.{region}.amazonaws.com"
                url    = f"https://{host}/v13/downloadCompleteLogFile/{instance_name}/{log_file_name}"
                awsreq = AWSRequest(method='GET', url=url)
                sigv4auth.add_auth(awsreq)

                req = urllib.request.Request(url, headers={
                    'Authorization':        awsreq.headers['Authorization'],
                    'Host':                 host,
                    'X-Amz-Date':           awsreq.context['timestamp'],
                    'X-Amz-Security-Token': credentials.token
                })

                # ログファイルをダウンロード
                with urllib.request.urlopen(req) as response:
                    log_data = response.read()

                # ファイルが空の場合は除外
                if len(log_data) == 0:
                    print(f"Log file {log_file_name} is empty. Skipping.")
                    continue

                # ログファイルを圧縮
                compressed_data = BytesIO()
                with gzip.GzipFile(fileobj=compressed_data, mode='wb') as f:
                    f.write(log_data)
                compressed_data.seek(0)

                # S3にアップロード
                s3_client.upload_fileobj(
                    Fileobj=compressed_data,
                    Bucket=S3_BUCKET,
                    Key=object_key
                )

    return {
        'statusCode': 200,
        'body': 'Audit log file processing completed.'
    }
