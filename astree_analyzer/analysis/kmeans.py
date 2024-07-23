import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.cluster import KMeans
import matplotlib.pyplot as plt

# Load the data
file_path = '../../output/merged_subtreesGit.csv'
df = pd.read_csv(file_path)

# Display the first few rows of the dataframe and the shape of the data
print(df.head())
print(f"Shape of the data: {df.shape}")

# Check if there are enough samples and features for PCA and clustering
if df.shape[0] < 2 or 'CountCommit' not in df.columns or 'CountComment' not in df.columns:
    raise ValueError("The dataset must contain at least two samples and both 'CountCommit' and 'CountComment' columns for clustering.")

# Extract the numeric columns for clustering
numeric_data = df[['CountCommit', 'CountComment']]

# Handle NaN values by filling them with the mean of the column
numeric_data.fillna(numeric_data.mean(), inplace=True)

# Standardize the data
scaler = StandardScaler()
scaled_data = scaler.fit_transform(numeric_data)

# Apply PCA to reduce the data to 2 dimensions
# Only proceed if there are more than one sample
if scaled_data.shape[0] > 1:
    pca = PCA(n_components=2)
    principal_components = pca.fit_transform(scaled_data)

    # Perform k-means clustering
    kmeans = KMeans(n_clusters=3, random_state=42)
    clusters = kmeans.fit_predict(principal_components)

    # Create a DataFrame with the PCA components and cluster assignments
    pca_df = pd.DataFrame(data=principal_components, columns=['PC1', 'PC2'])
    pca_df['Cluster'] = clusters

    # Plot the PCA components and color by cluster
    plt.figure(figsize=(10, 8))
    plt.scatter(pca_df['PC1'], pca_df['PC2'], c=pca_df['Cluster'], cmap='viridis', marker='o')
    plt.title('K-means Clustering of Subtrees')
    plt.xlabel('Principal Component 1')
    plt.ylabel('Principal Component 2')
    plt.colorbar(label='Cluster')
    plt.show()
else:
    print("Not enough samples for PCA and clustering.")
