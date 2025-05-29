import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import confusion_matrix
import pandas as pd

# Đọc dữ liệu từ file CSV
df = pd.read_csv("sample_wazuh_dataset.csv")

# Xử lý dữ liệu bị thiếu (NaN) bằng cách thay thế bằng chuỗi rỗng
df.fillna('', inplace=True)

# Chọn cột full_log và data_url làm feature, cột label làm target
# X = df[['full_log','data_url']]
# X = df.drop(['srcip', 'dstip'])
# y = df["label"]

# Kiểm tra các cột có tồn tại không trước khi drop
cols_to_drop = ['srcip', 'dstip', 'data_protocol']
X = df.drop(columns=[col for col in cols_to_drop if col in df.columns])

# Chọn cột label làm target
y = df["label"]

# Kiểm tra dữ liệu X trước khi tiếp tục
print("Columns in X:", X.columns)

# Chuyển toàn bộ dữ liệu thành chuỗi và ghép các cột thành một chuỗi duy nhất
X = X.astype(str).agg(' '.join, axis=1)

# Chuyển dữ liệu văn bản thành dạng vector TF-IDF
vectorizer = TfidfVectorizer()
X_vec = vectorizer.fit_transform(X)

# Chia dữ liệu thành tập huấn luyện và tập kiểm tra (80%/20%)
X_train, X_test, y_train, y_test = train_test_split(X_vec, y, test_size = 0.20, random_state = 42)

# Initialize Random Forest Classifier
model = RandomForestClassifier()
model.fit(X_train,y_train)

# Evaluate the best model on validation data
y_pred = model.predict(X_test)

# Đánh giá hiệu năng của mô hình
print("Accuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:")
print(classification_report(y_test, y_pred))
print("Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# # Save the model to disk
# joblib.dump(model, 'wazuh_classifier.joblib')
# print("Model saved to wazuh_classifier.joblib")

# # Save the vectorizer to disk
# joblib.dump(vectorizer, "tfidf_vectorizer.joblib")
# print("Vectorizer saved to tfidf_vectorizer.joblib")