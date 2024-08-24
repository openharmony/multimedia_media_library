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
#include "permission_utils.h"

namespace OHOS {
using namespace std;

static inline string FuzzString(const uint8_t *data, size_t size)
{
    return {reinterpret_cast<const char*>(data), size};
}

static inline int32_t FuzzInt32(const uint8_t *data)
{
    return static_cast<int32_t>(*data);
}

static inline double FuzzDouble(const uint8_t *data, size_t size)
{
    return static_cast<double>(*data);
}

static inline vector<string> FuzzVectorString(const uint8_t *data, size_t size)
{
    return {FuzzString(data, size)};
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
    string selection;
    Media::MediaLibraryCommonUtils::AppendSelections(selection);
}

static void PermissionUtilsTest(const uint8_t *data, size_t size)
{
    Media::PermissionUtils::CheckCallerPermission(FuzzString(data, size));
    string packageName;
    Media::PermissionUtils::GetPackageName(FuzzInt32(data), packageName);
    Media::PermissionUtils::CheckIsSystemAppByUid();
    Media::PermissionUtils::GetPackageNameByBundleName(FuzzString(data, size));
    Media::PermissionUtils::GetAppIdByBundleName(packageName);
    Media::PermissionUtils::IsSystemApp();
    Media::PermissionUtils::IsNativeSAApp();
    Media::PermissionUtils::IsRootShell();
    Media::PermissionUtils::IsHdcShell();
    Media::PermissionUtils::GetTokenId();
    Media::PermissionUtils::ClearBundleInfoInCache();
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
    Media::MediaFileUri::GetMediaTypeUri(static_cast<Media::MediaType>(FuzzInt32(data)), FuzzInt32(data));
    vector<string> timeIdBatch;
    int start = FuzzInt32(data);
    int count = FuzzInt32(data);
    Media::MediaFileUri::GetTimeIdFromUri(FuzzVectorString(data, size), timeIdBatch);
    Media::MediaFileUri::GetTimeIdFromUri(FuzzVectorString(data, size), timeIdBatch, start, count);
    Media::MediaFileUri::CreateAssetBucket(FuzzInt32(data), count);
    Media::MediaFileUri::GetPathFromUri(FuzzString(data, size), FuzzInt32(data));
}

static void ExifTest(const uint8_t *data, size_t size)
{
    Media::ExifUtils::WriteGpsExifInfo(FuzzString(data, size), FuzzDouble(data, size), FuzzDouble(data, size));
}

static void PhotoProxyTest(const uint8_t *data, size_t size)
{
    Media::PhotoAssetProxy proxy(nullptr, static_cast<Media::CameraShotType>(FuzzInt32(data)),
        FuzzInt32(data), FuzzInt32(data));
    proxy.GetFileAsset();
    proxy.GetPhotoAssetUri();
    proxy.GetVideoFd();
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
    // OHOS::DfxTest(data, size);
    OHOS::ExifTest(data, size);
    OHOS::PhotoProxyTest(data, size);
    return 0;
}
