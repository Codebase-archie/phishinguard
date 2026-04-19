import pandas as pd
import sys
from tqdm import tqdm
sys.path.append('src')
from features import extract_features

def build_dataset(input_path, output_path, sample_size=50000):
    print(f"Loading URLs from {input_path}...")
    df = pd.read_csv(input_path)
    
    # balance the dataset - equal phishing and benign
    phish = df[df['label'] == 1].sample(
        n=sample_size//2, random_state=42)
    benign = df[df['label'] == 0].sample(
        n=sample_size//2, random_state=42)
    df_balanced = pd.concat([phish, benign]).sample(
        frac=1, random_state=42).reset_index(drop=True)
    
    print(f"Balanced dataset: {len(df_balanced)} URLs")
    print(f"Phishing: {(df_balanced['label']==1).sum()}")
    print(f"Benign:   {(df_balanced['label']==0).sum()}")
    
    print("\nExtracting features...")
    features_list = []
    errors = 0
    
    for url in tqdm(df_balanced['url'], desc="Processing"):
        try:
            features = extract_features(url)
            features_list.append(features)
        except Exception:
            features_list.append(None)
            errors += 1
    
    print(f"\nErrors: {errors}")
    
    # build features dataframe
    features_df = pd.DataFrame(features_list)
    features_df['label'] = df_balanced['label'].values
    
    # drop any rows where extraction failed
    features_df = features_df.dropna()
    
    print(f"Final dataset shape: {features_df.shape}")
    print(f"\nFeature columns: {features_df.columns.tolist()}")
    
    features_df.to_csv(output_path, index=False)
    print(f"\nSaved to {output_path}")
    
    return features_df


if __name__ == "__main__":
    df = build_dataset(
        input_path='data/raw_urls.csv',
        output_path='data/features.csv',
        sample_size=100000
    )
    print("\nSample rows:")
    print(df.head(3))