import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import RFE
from sklearn.metrics import accuracy_score, confusion_matrix, roc_auc_score

# 1. Tải dataset (thay đường dẫn file bằng dataset của bạn)
dataset = pd.read_csv('dataset_malware.csv')  # Thay bằng đường dẫn tới file CSV của bạn

# 2. Chuẩn bị dữ liệu
# Loại bỏ các cột không phải đặc trưng (nếu có, ví dụ: 'Name', 'md5', 'legitimate')
X = dataset.drop(['Name', 'md5', 'legitimate'], axis=1).values  # Điều chỉnh tên cột theo dataset của bạn
y = dataset['legitimate'].values  # Nhãn phân loại

# Chia dữ liệu thành tập huấn luyện và tập kiểm tra
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, stratify=y, random_state=42)

# 3. Khởi tạo mô hình RandomForest
rf = RandomForestClassifier(n_estimators=50, random_state=42)

# 4. Áp dụng RFE để chọn 10 đặc trưng quan trọng nhất (có thể thay đổi số lượng)
selector = RFE(estimator=rf, n_features_to_select=10, step=1)
selector.fit(X_train, y_train)

# 5. Lấy các đặc trưng được chọn
X_train_rfe = selector.transform(X_train)
X_test_rfe = selector.transform(X_test)

# In danh sách các đặc trưng được chọn
feature_names = dataset.drop(['Name', 'md5', 'legitimate'], axis=1).columns
selected_features = selector.get_support(indices=True)
selected_feature_names = feature_names[selected_features]
print("Các đặc trưng được chọn:", selected_feature_names.tolist())

# 6. Huấn luyện mô hình với các đặc trưng được chọn
rf.fit(X_train_rfe, y_train)

# 7. Dự đoán và đánh giá hiệu suất
y_pred = rf.predict(X_test_rfe)
accuracy = accuracy_score(y_test, y_pred)
conf_matrix = confusion_matrix(y_test, y_pred)
auc = roc_auc_score(y_test, rf.predict_proba(X_test_rfe)[:, 1])

print("Độ chính xác (Accuracy):", accuracy)
print("Ma trận nhầm lẫn (Confusion Matrix):\n", conf_matrix)
print("Điểm AUC:", auc)