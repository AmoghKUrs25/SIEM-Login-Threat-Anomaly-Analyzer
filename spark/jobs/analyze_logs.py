
from pyspark.sql import SparkSession
from pyspark.sql.functions import (
    col,
    count,
    countDistinct,
    when,
    lit,
    to_timestamp,
    unix_timestamp,
    max as spark_max,
    window,
)

INPUT_PATH = "hdfs://namenode:9000/siem/raw/login_events.jsonl"
OUTPUT_PATH = "hdfs://namenode:9000/siem/processed/login_analysis"

spark = (
    SparkSession.builder
    .appName("SIEM-Login-Threat-Analyzer")
    .getOrCreate()
)

spark.sparkContext.setLogLevel("WARN")

# Read login events from HDFS.
logs = spark.read.json(INPUT_PATH)

# Parse timestamps and normalize status flags.
logs = (
    logs
    .withColumn(
        "event_time",
        to_timestamp(
            col("timestamp"),
            "yyyy-MM-dd'T'HH:mm:ss.SSSSSSXXX"
        )
    )
    .withColumn("event_epoch", unix_timestamp(col("event_time")))
    .withColumn(
        "is_failure",
        when(col("status") == "failure", 1).otherwise(0)
    )
    .withColumn(
        "is_success",
        when(col("status") == "success", 1).otherwise(0)
    )
)

# Overall statistics for every source IP.
ip_summary = (
    logs.groupBy("source_ip")
    .agg(
        count("*").alias("total_events"),
        spark_max("event_epoch").alias("last_seen_epoch"),
        countDistinct("username").alias("distinct_users"),
        count(when(col("status") == "failure", True)).alias("failed_logins"),
        count(when(col("status") == "success", True)).alias("successful_logins"),
    )
)

# Analyze failures in overlapping two-minute windows.
# A 30-second slide helps catch bursts across time boundaries.
failures = logs.filter(
    (col("status") == "failure") & col("event_time").isNotNull()
)

window_summary = (
    failures
    .groupBy(
        window(col("event_time"), "2 minutes", "30 seconds"),
        col("source_ip")
    )
    .agg(
        count("*").alias("window_failures"),
        countDistinct("username").alias("window_users")
    )
)

# Determine the strongest short-window pattern per source IP.
burst_summary = (
    window_summary
    .groupBy("source_ip")
    .agg(
        spark_max("window_failures").alias("max_window_failures"),
        spark_max("window_users").alias("max_window_users")
    )
)

ip_summary = ip_summary.join(
    burst_summary, on="source_ip", how="left"
).fillna({
    "max_window_failures": 0,
    "max_window_users": 0
})

# Rules use short-window evidence, not lifetime totals alone.
ip_summary = (
    ip_summary
    .withColumn(
        "threat_type",
        when(
            (col("max_window_failures") >= 5)
            & (col("max_window_users") == 1),
            lit("BRUTE_FORCE_CANDIDATE")
        )
        .when(
            (col("max_window_failures") >= 5)
            & (col("max_window_users") >= 3),
            lit("PASSWORD_SPRAY_CANDIDATE")
        )
        .otherwise(lit("NORMAL_OR_LOW_ACTIVITY"))
    )
    .withColumn(
        "risk_score",
        when(
            (col("max_window_failures") >= 10)
            & (col("max_window_users") == 1),
            90
        )
        .when(
            (col("max_window_failures") >= 5)
            & (col("max_window_users") >= 3),
            80
        )
        .when(col("max_window_failures") >= 5, 65)
        .otherwise(10)
    )
)

print("=== Login event count ===")
print(f"Total events: {logs.count()}")

print("=== Source IP threat summary ===")
ip_summary.orderBy(
    col("risk_score").desc(),
    col("max_window_failures").desc()
).show(50, truncate=False)

# Save results in Parquet format for later Hive queries.
(
    ip_summary
    .write
    .mode("overwrite")
    .parquet(OUTPUT_PATH)
)

print(f"Analysis results written to {OUTPUT_PATH}")

spark.stop()
