
from pyspark.sql import SparkSession

spark = (
    SparkSession.builder
    .appName("SIEM-HDFS-Connection-Test")
    .getOrCreate()
)

spark.sparkContext.setLogLevel("WARN")

path = "hdfs://namenode:9000/siem/raw/login_events.jsonl"

df = spark.read.json(path)

print("HDFS CONNECTION SUCCESSFUL")
print("Total login events:", df.count())

df.select(
    "event_id", "username", "source_ip", "status"
).show(5, truncate=False)

spark.stop()
