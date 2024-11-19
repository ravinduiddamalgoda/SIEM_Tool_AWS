import boto3

# Fetch logs
def get_logs(log_group, log_stream):
    client = boto3.client('logs')
    response = client.get_log_events(
        logGroupName=log_group,
        logStreamName=log_stream,
        startFromHead=True
    )
    return response['events']

def get_instance_metrics(instance_id, start_time, end_time, period=300):
    client = boto3.client('cloudwatch')
    metrics = ['CPUUtilization', 'NetworkIn', 'NetworkOut', 'DiskReadOps', 'DiskWriteOps']

    metric_data_queries = [
        {
            'Id': metric.lower(),
            'MetricStat': {
                'Metric': {
                    'Namespace': 'AWS/EC2',
                    'MetricName': metric,
                    'Dimensions': [{'Name': 'InstanceId', 'Value': instance_id}]
                },
                'Period': period,
                'Stat': 'Average',
            },
            'ReturnData': True,
        }
        for metric in metrics
    ]

    response = client.get_metric_data(
        MetricDataQueries=metric_data_queries,
        StartTime=start_time,
        EndTime=end_time,
    )
    return response['MetricDataResults']
