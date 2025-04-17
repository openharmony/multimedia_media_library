/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "medialibrary_common_fuzzer.h"

#include <cstdint>
#include <string>

#include "dfx_database_utils.h"
#include "exif_utils.h"
#include "media_log.h"
#include "media_photo_asset_proxy.h"
#include "media_scanner_manager.h"
#include "medialibrary_common_utils.h"
#include "media_file_uri.h"
#include "medialibrary_data_manager_utils.h"

#define private public
#include "permission_utils.h"
#include "photo_file_utils.h"
#undef private

namespace OHOS {
using namespace std;
const int32_t EVEN = 2;
const std::string PERMISSION = "testName";
const std::string ROOT_MEDIA_DIR = "/storage/cloud/files/";
const std::string PHOTO_PATH = "/Photo/5/IMG_1741264239_005.jpg";
static inline string FuzzString(const uint8_t *data, size_t size)
{
    return {reinterpret_cast<const char*>(data), size};
}

static inline int32_t FuzzInt32(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return 0;
    }
    return static_cast<int32_t>(*data);
}

static inline int64_t FuzzInt64(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return 0;
    }
    return static_cast<int64_t>(*data);
}

static inline bool FuzzBool(const uint8_t* data, size_t size)
{
    if (size == 0) {
        return false;
    }
    return (data[0] % EVEN) == 0;
}

static inline double FuzzDouble(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(double)) {
        return 0.0;
    }
    return static_cast<double>(*data);
}

static inline vector<string> FuzzVectorString(const uint8_t *data, size_t size)
{
    return {FuzzString(data, size)};
}

static inline vector<uint8_t> FuzzVectorUint8(const uint8_t *data, size_t size)
{
    return {*data};
}

static inline Security::AccessToken::PermissionUsedType FuzzPermissionUsedType(const uint8_t *data, size_t size)
{
    int32_t value = FuzzInt32(data, size);
    if (value >= static_cast<int32_t>(Security::AccessToken::PermissionUsedType::NORMAL_TYPE) &&
        value <= static_cast<int32_t>(Security::AccessToken::PermissionUsedType::PERM_USED_TYPE_BUTT)) {
        return static_cast<Security::AccessToken::PermissionUsedType>(value);
    }
    return Security::AccessToken::PermissionUsedType::INVALID_USED_TYPE;
}

static void ScanTest(const uint8_t *data, size_t size)
{
    auto scannerManager = Media::MediaScannerManager::GetInstance();
    if (scannerManager != nullptr) {
        scannerManager->ScanDir(FuzzString(data, size), nullptr);
    }
}

static void CommonUtilsTest(const uint8_t *data, size_t size)
{
    Media::MediaLibraryCommonUtils::CheckWhereClause(FuzzString(data, size));
    string key;
    Media::MediaLibraryCommonUtils::GenKeySHA256(FuzzString(data, size), key);
    Media::MediaLibraryCommonUtils::GenKeySHA256(FuzzVectorUint8(data, size), key);
    string selection;
    Media::MediaLibraryCommonUtils::AppendSelections(selection);
}

static void DfxTest(const uint8_t *data, size_t size)
{
    const int32_t int32Count = 5;
    if (data == nullptr || size < sizeof(int32_t) * int32Count) {
        return;
    }
    int32_t offset = 0;
    int32_t mediaType = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t position = FuzzInt32(data + offset, size);
    Media::DfxDatabaseUtils::QueryFromPhotos(mediaType, position);
    offset += sizeof(int32_t);
    int32_t albumSubtype = FuzzInt32(data + offset, size);
    Media::DfxDatabaseUtils::QueryAlbumInfoBySubtype(albumSubtype);
    Media::DfxDatabaseUtils::QueryDirtyCloudPhoto();
    Media::DfxDatabaseUtils::QueryAnalysisVersion(FuzzString(data, size), FuzzString(data, size));
    int32_t downloadedThumb;
    int32_t generatedThumb;
    Media::DfxDatabaseUtils::QueryDownloadedAndGeneratedThumb(downloadedThumb, generatedThumb);
    int32_t totalDownload;
    Media::DfxDatabaseUtils::QueryTotalCloudThumb(totalDownload);
    Media::DfxDatabaseUtils::QueryDbVersion();
    offset += sizeof(int32_t);
    int32_t imageCount = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t videoCount = FuzzInt32(data + offset, size);
    Media::PhotoRecordInfo info = {
        .imageCount = imageCount,
        .videoCount = videoCount
    };
    Media::DfxDatabaseUtils::QueryPhotoRecordInfo(info);
}

static void PermissionUtilsTest(const uint8_t *data, size_t size)
{
    Media::PermissionUtils::CheckCallerPermission(FuzzString(data, size));
    std::vector<std::string> perms;
    Media::PermissionUtils::CheckCallerPermission(perms);
    Media::PermissionUtils::CheckPhotoCallerPermission(perms);
    Media::PermissionUtils::CheckPhotoCallerPermission(FuzzString(data, size));
    Media::PermissionUtils::CheckHasPermission(perms);
    perms.push_back(FuzzString(data, size));
    Media::PermissionUtils::CheckHasPermission(perms);
    string packageName = FuzzString(data, size);
    const int32_t int32Count = 4;
    if (data == nullptr || size < sizeof(int32_t) * int32Count + sizeof(int64_t)) {
        return;
    }
    int32_t offset = 0;
    int uid = FuzzInt32(data + offset, size);
    Media::PermissionUtils::GetPackageName(uid, packageName);
    Media::PermissionUtils::CheckIsSystemAppByUid();
    Media::PermissionUtils::GetPackageNameByBundleName(FuzzString(data, size));
    Media::PermissionUtils::GetAppIdByBundleName(packageName);
    Media::PermissionUtils::IsSystemApp();
    Media::PermissionUtils::IsNativeSAApp();
    Media::PermissionUtils::IsRootShell();
    Media::PermissionUtils::IsHdcShell();
    Media::PermissionUtils::GetTokenId();
    Media::PermissionUtils::ClearBundleInfoInCache();
    bool permGranted = FuzzBool(data, size);
    offset += sizeof(int32_t);
    int32_t permissionUsedType = FuzzInt32(data + offset, size);
    Media::PermissionUtils::CollectPermissionInfo(FuzzString(data, size), permGranted,
        static_cast<Security::AccessToken::PermissionUsedType>(permissionUsedType));
    Media::PermissionUtils::UpdatePackageNameInCache(uid, packageName);

    std::string appId = FuzzString(data, size);
    offset += sizeof(int64_t);
    int64_t tokenId = FuzzInt64(data + offset, size);
    Media::PermissionUtils::GetMainTokenId(appId, tokenId);

    std::string permission = FuzzString(data, size);
    offset += sizeof(int32_t);
    Security::AccessToken::PermissionUsedType type = FuzzPermissionUsedType(data + offset, size);
    Media::PermissionUtils::CollectPermissionInfo(permission, permGranted, type);

    offset += sizeof(int32_t);
    Security::AccessToken::AccessTokenID tokenCaller = FuzzInt32(data + offset, size);
    Media::PermissionUtils::CheckPhotoCallerPermission(perms, uid, tokenCaller);

    permission = FuzzBool(data, size) ? PERMISSION : FuzzString(data, size);
    Media::PermissionUtils::CheckPhotoCallerPermission(permission, tokenCaller);
    Media::PermissionUtils::SetEPolicy();
}

static void FileUriTest(const uint8_t *data, size_t size)
{
    string uriStr = FuzzString(data, size);
    Media::MediaFileUri fileUri(uriStr);
    fileUri.GetFilePath();
    fileUri.GetFileId();
    fileUri.GetTableName();
    Media::MediaFileUri::GetPhotoId(FuzzString(data, size));
    Media::MediaFileUri::RemoveAllFragment(uriStr);
    const int32_t int32Count = 6;
    if (data == nullptr || size < sizeof(int32_t) * int32Count) {
        return;
    }
    int32_t offset = 0;
    int32_t mediaType = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t apiVersion = FuzzInt32(data + offset, size);
    Media::MediaFileUri::GetMediaTypeUri(static_cast<Media::MediaType>(mediaType), apiVersion);
    vector<string> timeIdBatch;

    offset += sizeof(int32_t);
    int start = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int count = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    Media::MediaFileUri::GetTimeIdFromUri(FuzzVectorString(data, size), timeIdBatch);
    Media::MediaFileUri::GetTimeIdFromUri(FuzzVectorString(data, size), timeIdBatch, start, count);
    int32_t fileId = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t isPhoto = FuzzInt32(data + offset, size);
    Media::MediaFileUri::CreateAssetBucket(fileId, count);
    Media::MediaFileUri::GetPathFromUri(FuzzString(data, size), isPhoto);
}

static void ExifTest(const uint8_t *data, size_t size)
{
    const double doubleCount = 2;
    if (data == nullptr || size < sizeof(double) * doubleCount) {
        return;
    }
    size_t offset = 0;
    double longitude = FuzzDouble(data + offset, size);
    offset += sizeof(double);
    double latitude = FuzzDouble(data + offset, size);
    Media::ExifUtils::WriteGpsExifInfo(FuzzString(data, size), longitude, latitude);
}

static void PhotoProxyTest(const uint8_t *data, size_t size)
{
    const int32_t int32Count = 3;
    if (data == nullptr || size < sizeof(int32_t) * int32Count) {
        return;
    }
    int32_t offset = 0;
    int32_t cameraShotType = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    uint32_t callingUid = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t userId = FuzzInt32(data + offset, size);
    Media::PhotoAssetProxy proxy(nullptr, static_cast<Media::CameraShotType>(cameraShotType),
        callingUid, userId);
    proxy.GetFileAsset();
    proxy.GetPhotoAssetUri();
    proxy.GetVideoFd();
}

static void PhotoFileUtilsTest(const uint8_t *data, size_t size)
{
     const int32_t int32Count = 2;
    if (data == nullptr || size < sizeof(int32_t) * int32Count + sizeof(int64_t)) {
        return;
    }
    int offset = 0;
    std::string photoPath = FuzzBool(data, size) ? ROOT_MEDIA_DIR : FuzzString(data, size);
    int32_t userId = FuzzInt32(data + offset, size);
    Media::PhotoFileUtils::GetEditDataPath(photoPath, userId);
    Media::PhotoFileUtils::GetEditDataCameraPath(photoPath, userId);
    Media::PhotoFileUtils::GetEditDataSourcePath(photoPath, userId);

    offset += sizeof(int64_t);
    int64_t editTime = FuzzInt64(data + offset, size);
    Media::PhotoFileUtils::HasEditData(editTime);
    bool hasEditDataCamera = FuzzBool(data, size);
    offset += sizeof(int32_t);
    int32_t effectMode = FuzzInt32(data + offset, size);
    Media::PhotoFileUtils::HasSource(hasEditDataCamera, editTime, effectMode);

    photoPath = FuzzBool(data, size) ? "" : FuzzString(data, size);
    Media::PhotoFileUtils::GetMetaDataRealPath(photoPath, userId);
    photoPath = PHOTO_PATH;
    Media::PhotoFileUtils::GetMetaDataRealPath(photoPath, userId);

    photoPath = FuzzBool(data, size) ? ROOT_MEDIA_DIR : "";
    Media::PhotoFileUtils::IsThumbnailExists(photoPath);
    photoPath = FuzzString(data, size);
    Media::PhotoFileUtils::IsThumbnailExists(photoPath);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::ScanTest(data, size);
    OHOS::CommonUtilsTest(data, size);
    OHOS::PermissionUtilsTest(data, size);
    OHOS::FileUriTest(data, size);
    OHOS::DfxTest(data, size);
    OHOS::ExifTest(data, size);
    OHOS::PhotoProxyTest(data, size);
    OHOS::PhotoFileUtilsTest(data, size);
    return 0;
}
