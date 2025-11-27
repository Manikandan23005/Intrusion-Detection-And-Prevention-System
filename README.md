# Intrusion Detection System — Detailed Explanation and Run Guide

## Project Overview
This repository implements an Intrusion Detection System (IDS) that detects malicious network activity from packet/flow data using supervised machine learning (or hybrid rule+ML). It supports training models from labeled datasets and running detection in batch or streaming modes.

## Architecture & Components
- Data ingestion: pcap/flow, CSV, or exported features (NetFlow/IPFIX, Zeek logs).
- Preprocessing: feature extraction, normalization, categorical encoding, windowing for flows.
- Model training: trains ML models (e.g., RandomForest, XGBoost, or neural networks) on prepared features.
- Detection/Inference: runs model predictions on incoming data and produces alerts.
- Evaluation: computes metrics (precision, recall, F1, ROC/AUC, confusion matrix).
- Deployment: options for batch CLI, simple HTTP API, or real-time packet capture pipeline.

Typical folder layout (example)
- src/                — core code (preprocessing, training, infer)
- data/               — raw and processed datasets
- models/             — trained model artifacts
- configs/            — experiment/config files
- notebooks/          — EDA and experiments
- utils/              — helpers (metrics, logging)

## Data & Recommended Datasets
Use labeled network datasets such as:
- CICIDS2017 / CIC-IDS2018
- NSL-KDD (smaller, useful for testing)
- UNSW-NB15
Prepare a CSV/Parquet of features per flow or per time-window. Required columns typically include: src_ip, dst_ip, src_port, dst_port, proto, duration, packet_count, byte_count, plus engineered features.

## Installation
Prerequisites:
- Python 3.8+
- pip, virtualenv (recommended)
- (Optional) GPU for deep-learning models

Quick install:
- Create virtual env:
  python -m venv .venv
  source .venv/bin/activate
- Install dependencies:
  pip install -r requirements.txt

(If requirements.txt is not present, add commonly used packages: pandas, scikit-learn, xgboost, numpy, joblib, scapy, pyshark, tqdm)

## Data Preparation
1. Place raw dataset under data/raw/ (e.g., pcap files or CSVs).
2. Run preprocessing:
   - python src/preprocess.py --input data/raw/ --output data/processed/
   This should:
   - extract flows (if pcap): e.g., using Zeek or a flow exporter
   - compute features (duration, packet counts, statistical features)
   - encode labels and save train/test splits

Expected outputs: data/processed/train.csv, data/processed/test.csv

## Training
Train a model from

![Project Preview](FlowChart.png)
