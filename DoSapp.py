import streamlit as st
import pandas as pd
import numpy as np
import uuid
import requests
from datetime import datetime, timedelta, timezone
from sklearn.ensemble import IsolationForest
from influxdb_client import InfluxDBClient
from streamlit_autorefresh import st_autorefresh
import plotly.express as px

# --- Page Setup ---
st.set_page_config(page_title="DOS Anomaly Detection Dashboard", layout="wide")

# --- InfluxDB Setup ---
INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
INFLUXDB_ORG = "Anormally Detection"
INFLUXDB_BUCKET = "realtime"
INFLUXDB_TOKEN = "DfmvA8hl5EeOcpR-d6c_ep6dRtSRbEcEM_Zqp8-1746dURtVqMDGni4rRNQbHouhqmdC7t9Kj6Y-AyOjbBg-zg=="
MEASUREMENT = "network_traffic"
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1383262825534984243/mMaPgCDV7tgEMsT_-5ABWpnxMJB746kM_hQqFa2F87lRKeBqCx9vyGY6sEyoY4NnZ7d7"

# --- Helper Functions ---
def query_influx(start_range="-1h", limit=300):
    try:
        with InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG) as client:
            query = f'''
            from(bucket: "{INFLUXDB_BUCKET}")
              |> range(start: {start_range})
              |> filter(fn: (r) => r._measurement == "{MEASUREMENT}")
              |> filter(fn: (r) =>
                   r._field == "packet_rate" or
                   r._field == "packet_length" or
                   r._field == "inter_arrival_time")
              |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
              |> sort(columns: ["_time"], desc: false)
              |> limit(n: {limit})
            '''
            df = client.query_api().query_data_frame(query)
            df = df.rename(columns={"_time": "timestamp"})
            if df.empty:
                return pd.DataFrame()
            expected = {"packet_rate", "packet_length", "inter_arrival_time"}
            missing = expected - set(df.columns)
            if missing:
                st.error(f"InfluxDB error: missing fields: {sorted(missing)}")
                return pd.DataFrame()
            return df.dropna(subset=list(expected))
    except Exception as e:
        st.error(f"InfluxDB error: {e}")
        return pd.DataFrame()

def detect_anomalies(df):
    required_cols = {"packet_rate", "packet_length", "inter_arrival_time"}
    if df.empty or not required_cols.issubset(df.columns):
        return pd.DataFrame()
    X = df[["packet_rate", "packet_length", "inter_arrival_time"]]
    model = IsolationForest(n_estimators=100, contamination=0.15, random_state=42)
    model.fit(X)
    df["anomaly_score"] = model.decision_function(X)
    df["anomaly"] = (model.predict(X) == -1).astype(int)
    return df

# --- Sidebar Controls ---
time_range_query_map = {
    "Last 30 min": "-30m",
    "Last 1 hour": "-1h",
    "Last 24 hours": "-24h",
    "Last 7 days": "-7d"
}

st.sidebar.header("Settings")
alerts_enabled = st.sidebar.checkbox("Enable Discord Alerts", value=True)
highlight_enabled = st.sidebar.checkbox("Highlight Anomalies", value=True)
highlight_color = st.sidebar.selectbox("Anomaly Highlight Color", ["red", "orange", "yellow", "blue", "green"], index=4)
time_range = st.sidebar.selectbox("Time Range", list(time_range_query_map.keys()), index=1)
thresh = st.sidebar.slider("Anomaly Score Threshold", -1.0, 1.0, -0.1, 0.01)

# --- Session State Init ---
# Removed prediction cache logic to prevent duplicate tab rendering

if "predictions" not in st.session_state or st.session_state.last_time_range != time_range:
    df = query_influx(time_range_query_map[time_range])
    st.session_state.predictions = detect_anomalies(df).to_dict("records")
    st.session_state.last_time_range = time_range

# --- Tabs ---
tabs = st.tabs(["Overview", "Live Stream", "Manual Entry", "Metrics & Alerts", "Historical Data"])

# --- Overview Tab ---
@st.cache_data(ttl=600)
def cached_data(time_range):
    return query_influx(time_range_query_map[time_range], limit=3000)

with tabs[0]:
    st.title("DOS Anomaly Detection Dashboard")
    df = cached_data(time_range)
    df = detect_anomalies(df)
    if df.empty:
        st.warning("No data found for the selected time range. Please adjust the time range in the sidebar.")
    else:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        filtered = df.copy()

        col1, col2, col3 = st.columns(3)
        col1.metric("Total Records", len(filtered))
        col2.metric("Anomaly Rate", f"{filtered['anomaly'].mean():.2%}")
        col3.metric("Recent Attacks", filtered["anomaly"].sum())

        rows_per_page = 50
        total_rows = len(filtered)
        total_pages = (total_rows - 1) // rows_per_page + 1
        page = st.number_input("Overview Page", min_value=1, max_value=total_pages, value=1, step=1) - 1
        start_idx, end_idx = page * rows_per_page, (page + 1) * rows_per_page
        display_df = filtered.iloc[start_idx:end_idx]

        def highlight_overview_anomaly(row):
            return [f"background-color: {highlight_color}" if row["anomaly"] == 1 else ""] * len(row)

        st.dataframe(display_df.style.apply(highlight_overview_anomaly, axis=1) if highlight_enabled else display_df)

        st.subheader("Time Series Analysis")
        selected_vars = st.multiselect("Select metrics to display:",
                                       options=["packet_rate", "packet_length", "inter_arrival_time"],
                                       default=["packet_rate", "packet_length"])
        if selected_vars:
            fig = px.line(filtered, x="timestamp", y=selected_vars, color="anomaly",
                          labels={"packet_rate": "Packet Rate", "packet_length": "Packet Length", "inter_arrival_time": "Inter-Arrival Time"},
                          title="DoS Metrics Over Time")
            fig.add_hline(y=thresh, line_dash="dash", line_color="black", annotation_text=f"Threshold ({thresh})")
            st.plotly_chart(fig, use_container_width=True)

# --- Live Stream Tab ---
with tabs[1]:
    st_autorefresh(interval=30000, key="live_stream_refresh")
    live_df = query_influx(start_range="-10s", limit=100)
    if not live_df.empty:
        result = detect_anomalies(live_df)
        attacks = result[result["anomaly"] == 1]
        if not attacks.empty:
            new_entries = attacks.to_dict("records")
            for row in new_entries:
                st.session_state.predictions.append(row)
                if alerts_enabled:
                    message = {
                        "content": f"""DoS Anomaly Detected!
Timestamp: {row['timestamp']}
Packet Rate: {row['packet_rate']}
Packet Length: {row['packet_length']}
Inter-arrival Time: {row['inter_arrival_time']}"""
                    }
                    try:
                        requests.post(DISCORD_WEBHOOK, json=message, timeout=5)
                    except Exception as e:
                        st.warning(f"Discord alert failed: {e}")
                    st.warning(f"Attack detected at {row['timestamp']}")
            st.dataframe(pd.DataFrame(new_entries))
        else:
            st.info("No real-time data available.")
    else:
        st.info("No real-time data available.")

# --- Manual Entry Tab ---
with tabs[2]:
    st.header("Manual Testing")
    col1, col2, col3 = st.columns(3)
    with col1:
        packet_rate = st.number_input("Packet Rate", value=50.0)
    with col2:
        packet_length = st.number_input("Packet Length", value=500.0)
    with col3:
        inter_arrival_time = st.number_input("Inter-Arrival Time", value=0.02)

    if st.button("Predict Anomaly"):
        test = pd.DataFrame([[packet_rate, packet_length, inter_arrival_time]],
                            columns=["packet_rate", "packet_length", "inter_arrival_time"])
        result = detect_anomalies(test).iloc[0].to_dict()
        result["timestamp"] = datetime.now().isoformat()
        st.session_state.predictions.append(result)
        if alerts_enabled and result["anomaly"] == 1:
            message = {
    "content": f"""DoS Anomaly Detected!
Timestamp: {result['timestamp']}
Packet Rate: {result['packet_rate']}
Packet Length: {result['packet_length']}
Inter-arrival Time: {result['inter_arrival_time']}"""
}
            try:
                requests.post(DISCORD_WEBHOOK, json=message, timeout=5)
            except Exception as e:
                st.warning(f"Discord alert failed: {e}")
        st.success("Prediction complete. Result stored.")

# --- Metrics & Alerts Tab ---
with tabs[3]:
    st.header("Analytical Dashboard")
    df = pd.DataFrame(st.session_state.predictions)
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        pie = px.pie(df, names=df["anomaly"].map({0: "Normal", 1: "Attack"}), title="Anomaly Distribution")
        st.plotly_chart(pie)

        line = px.line(df, x="timestamp", y="anomaly_score", title="Anomaly Score Over Time")
        st.plotly_chart(line)
    else:
        st.info("No prediction data available.")

# --- Cached Historical Data ---
@st.cache_data(ttl=600)
def cached_historical():
    return query_influx("-30d", limit=3000)

with tabs[4]:
    st.subheader("DOS Historical Data")
    df_hist = cached_historical()
    if not df_hist.empty:
        df_hist = detect_anomalies(df_hist)
        df_hist["timestamp"] = pd.to_datetime(df_hist["timestamp"])

        total_records = len(df_hist)
        anomaly_rate = df_hist["anomaly"].mean()
        total_attacks = df_hist["anomaly"].sum()

        col1, col2, col3 = st.columns(3)
        col1.metric("Total Records (All Time)", total_records)
        col2.metric("Anomaly Rate (All Time)", f"{anomaly_rate:.2%}")
        col3.metric("Total Attacks", total_attacks)

        rows_per_page = 100
        total_pages = (total_records - 1) // rows_per_page + 1
        page = st.number_input("Historical Page", min_value=1, max_value=total_pages, value=1, step=1) - 1
        start_idx, end_idx = page * rows_per_page, (page + 1) * rows_per_page
        display_df = df_hist.iloc[start_idx:end_idx]

        def highlight_anomaly(row):
            return [f"background-color: {highlight_color}" if row["anomaly"] == 1 else ""] * len(row)

        st.dataframe(display_df.style.apply(highlight_anomaly, axis=1))

        chart_type = st.selectbox("Select chart type", ["Line Chart", "Bar Chart", "Pie Chart", "Area Chart", "Graph"], index=0)
        y_label_map = {
            "packet_rate": "Packet Rate",
            "packet_length": "Packet Length",
            "inter_arrival_time": "Inter-Arrival Time"
        }

        if chart_type == "Line Chart":
            fig = px.line(df_hist, x="timestamp", y="packet_rate", labels=y_label_map,
                          color="anomaly",
                          color_discrete_map={0: "#1f77b4", 1: "red"},
                          title="Historical DoS Metrics Over Time")
        elif chart_type == "Bar Chart":
            fig = px.bar(df_hist, x="timestamp", y="packet_rate",
                         color="anomaly",
                         color_discrete_map={0: "#1f77b4", 1: "red"},
                         title="Packet Rate Over Time")
        elif chart_type == "Pie Chart":
            fig = px.pie(df_hist, names=df_hist["anomaly"].map({0: "Normal", 1: "Attack"}),
                         title="Anomaly Distribution in Historical Data")
        elif chart_type == "Graph":
            fig = px.scatter(df_hist, x="timestamp", y="packet_rate",
                             color="anomaly",
                             color_discrete_map={0: "#1f77b4", 1: "red"},
                             title="Packet Rate Scatter Plot")
        elif chart_type == "Area Chart":
            fig = px.area(df_hist, x="timestamp", y="packet_rate",
                         color="anomaly",
                         color_discrete_map={0: "#1f77b4", 1: "red"},
                         title="Packet Rate Area Chart")
        st.plotly_chart(fig, use_container_width=True)

        csv_data = df_hist.to_csv(index=False)
        st.download_button("Download CSV", csv_data, "dos_historical_data.csv", "text/csv")
    else:
        st.warning("No historical data available.")
