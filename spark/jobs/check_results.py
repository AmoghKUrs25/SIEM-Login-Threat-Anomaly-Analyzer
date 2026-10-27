
from pyspark.sql import SparkSession

spark = (
    SparkSession.builder
    .appName("SIEM-Check-Results")
    .getOrCreate()
)

spark.sparkContext.setLogLevel("WARN")

path = "hdfs://namenode:9000/siem/processed/login_analysis"

results = spark.read.parquet(path)

results.orderBy("risk_score", ascending=False).show(
    20, truncate=False
)

spark.stop()
