import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from sklearn.feature_extraction.text import TfidfVectorizer

# Bước 1: Đọc dữ liệu từ file
df = pd.read_csv("dataset.csv")

# Bước 2: Gộp dữ liệu đầu vào
df = df.fillna('')  # xử lý giá trị NaN
X_text = df[['full_log', 'data_url']].astype(str).agg(' '.join, axis=1)  # nối hai cột thành chuỗi

# Bước 3: Vector hóa dữ liệu text
vectorizer = TfidfVectorizer()
X_vec = vectorizer.fit_transform(X_text)

# chỗ này t viết là cứ có chèn payload thì label 1, ngược lại label 0
y = df["label"]

# Bước 5: Chia dữ liệu train/test
X_train, X_test, y_train, y_test = train_test_split(X_vec, y, test_size=0.3, random_state=42)

# Bước 6: Huấn luyện mô hình
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Bước 7: Đánh giá mô hình
y_pred = model.predict(X_test)
print("🎯 Accuracy:", accuracy_score(y_test, y_pred))
print("📋 Classification Report:\n", classification_report(y_test, y_pred))
print("📊 Confusion Matrix:\n", confusion_matrix(y_test, y_pred))

# Bước 8: Lưu mô hình và vectorizer
joblib.dump(model, "wazuh_classifier.joblib")
joblib.dump(vectorizer, "tfidf_vectorizer.joblib")
print("✅ Đã lưu mô hình và vectorizer!")