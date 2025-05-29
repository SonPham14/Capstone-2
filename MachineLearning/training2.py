import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.svm import SVC
from sklearn.metrics import classification_report, accuracy_score

# Đọc dữ liệu từ file CSV
df = pd.read_csv("dataset.csv")

# Chỉ thay thế NaN trong các cột kiểu chuỗi (cách mới, đúng chuẩn Pandas 3.0)
df.fillna({col: '' for col in df.select_dtypes(include=['object']).columns}, inplace=True)

# Kiểm tra kiểu dữ liệu của từng cột
print(df.dtypes)

# # Xử lý cột label để đảm bảo nó chứa giá trị hợp lệ
# if df['label'].dtype == 'float64':  # Nếu là số thực, chuyển thành số nguyên
#     df['label'] = df['label'].fillna(0).astype(int)
# else:  # Nếu là chuỗi, thay thế NaN bằng "unknown"
#     df['label'] = df['label'].fillna('unknown').astype(str)

# Kiểm tra giá trị trong cột label
print(df['label'].unique())

# Chọn cột feature (loại bỏ các cột không mong muốn nếu có)
cols_to_drop = ['srcip', 'dstip']
X = df.drop(columns=[col for col in cols_to_drop if col in df.columns])

# Chọn cột label làm target
y = df["label"]

# Kiểm tra lại X trước khi vector hóa
print("Columns in X:", X.columns)

# Chuyển toàn bộ dữ liệu thành chuỗi và ghép các cột thành một chuỗi duy nhất
X = X.astype(str).agg(' '.join, axis=1)

# Chuyển dữ liệu văn bản thành dạng vector TF-IDF
vectorizer = TfidfVectorizer()
X_vec = vectorizer.fit_transform(X)

# Chia dữ liệu thành tập huấn luyện và tập kiểm tra (80%/20%)
X_train, X_test, y_train, y_test = train_test_split(X_vec, y, test_size=0.2, random_state=42)

# 🔹 1️⃣ Mô hình Random Forest
rf_model = RandomForestClassifier()
rf_model.fit(X_train, y_train)
y_pred_rf = rf_model.predict(X_test)
print("\n🔹 Random Forest Results:")
print("Accuracy:", accuracy_score(y_test, y_pred_rf))
print(classification_report(y_test, y_pred_rf))

# 🔹 2️⃣ Mô hình XGBoost
xgb_model = XGBClassifier(eval_metric='mlogloss')
xgb_model.fit(X_train, y_train)
y_pred_xgb = xgb_model.predict(X_test)
print("\n🔹 XGBoost Results:")
print("Accuracy:", accuracy_score(y_test, y_pred_xgb))
print(classification_report(y_test, y_pred_xgb))

# 🔹 3️⃣ Mô hình SVM
# svm_model = SVC(kernel='linear', probability=True)
# svm_model.fit(X_train, y_train)
# y_pred_svm = svm_model.predict(X_test)
# print("\n🔹 SVM Results:")
# print("Accuracy:", accuracy_score(y_test, y_pred_svm))
# print(classification_report(y_test, y_pred_svm))

# # Save the model to disk
# joblib.dump(model, 'wazuh_classifier.joblib')
# print("Model saved to wazuh_classifier.joblib")

# # Save the vectorizer to disk
# joblib.dump(vectorizer, "tfidf_vectorizer.joblib")
# print("Vectorizer saved to tfidf_vectorizer.joblib")

# Lưu mô hình tốt nhất
# joblib.dump(rf_model, 'random_forest_model.joblib')
# joblib.dump(xgb_model, 'xgboost_model.joblib')
# # joblib.dump(svm_model, 'svm_model.joblib')
# joblib.dump(vectorizer, "tfidf_vectorizer.joblib")