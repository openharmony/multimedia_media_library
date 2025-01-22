/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef PHOTO_ACCESS_HELPER_UTILS_H
#define PHOTO_ACCESS_HELPER_UTILS_H

#include <cstdint>
#include <memory>
#include <string>

#include "cj_common_ffi.h"
#include "cj_data_ffi.h"
#include "data_share_predicates_impl.h"
#include "datashare_predicates.h"
#include "datashare_result_set.h"
#include "ffi_remote_data.h"
#include "photo_accesshelper_log.h"
#include "media_file_uri.h"
#include "media_file_utils.h"
#include "medialibrary_client_errno.h"
#include "medialibrary_napi_utils.h"
#include "medialibrary_type_const.h"
#include "userfile_client.h"
#include "userfile_manager_types.h"

namespace OHOS {
namespace Media {
extern "C" {
enum FfiListenerType {
    CJ_INVALID_LISTENER = -1,
    CJ_AUDIO_LISTENER,
    CJ_VIDEO_LISTENER,
    CJ_IMAGE_LISTENER,
    CJ_FILE_LISTENER,
    CJ_SMARTCJ_ALBUM_LISTENER,
    CJ_DEVICE_LISTENER,
    CJ_REMOTECJ_FILE_LISTENER,
    CJ_ALBUM_LISTENER
};

enum class ReturnDataType {
    TYPE_IMAGE_SOURCE = 0,
    TYPE_ARRAY_BUFFER,
    TYPE_MOVING_PHOTO,
    TYPE_TARGET_PATH,
    TYPE_PICTURE,
};

enum class DeliveryMode {
    FAST = 0,
    HIGH_QUALITY,
    BALANCED_MODE,
};

enum class SourceMode {
    ORIGINAL_MODE = 0,
    EDITED_MODE,
};

enum class SingleSelectionMode {
    BROWSER_MODE = 0,
    SELECT_MODE,
    BROWSER_AND_SELECT_MODE,
};

struct CSize {
    int32_t width = 0;
    int32_t height = 0;
};

struct PhotoAssetMember {
    int32_t memberType;
    int64_t intValue;
    char* stringValue;
    bool boolValue;
};

struct FetchResultObject {
    int64_t id;
    int32_t fetchResType;
};

struct CArrayFetchResultObject {
    FetchResultObject* head;
    int64_t size;
};

struct COptions {
    CArrString fetchColumns;
    int64_t predicates;
};

struct CreateOptions {
    char* title;
    int32_t subtype;
};

struct ChangeData {
    int32_t type;
    CArrString uris;
    CArrString extraUris;
};

struct PhotoCreationConfig {
    char* title;
    char* fileNameExtension;
    int32_t photoType;
    int32_t subtype;
};

struct PhotoCreationConfigs {
    PhotoCreationConfig* head;
    int64_t size;
};

struct FfiBundleInfo {
    char* bundleName;
    char* appName;
    char* appId;
};

struct TextContextInfo {
    char* text;
};

struct RecommendationOptions {
    int32_t recommendationType;
    TextContextInfo textContextInfo;
};

struct PhotoSelectOptions {
    int32_t MIMEType;
    int32_t maxSelectNumber;
    bool isPhotoTakingSupported;
    bool isSearchSupported;
    RecommendationOptions recommendationOptions;
    CArrString preselectedUris;
    bool isPreviewForSingleSelectionSupported;
    SingleSelectionMode singleSelectionMode;
    bool isEditSupported;
    bool isOriginalSupported;
    char* subWindowName;
};

struct PhotoSelectResult {
    CArrString photoUris;
    bool isOriginalPhoto;
};

struct RequestOptions {
    int32_t deliveryMode;
};

struct KeyValue {
    char* key;
    char* value;
};

struct HashMapArray {
    KeyValue* head;
    int64_t size;
};

struct MediaObject {
    ReturnDataType returnDataType;
    CArrUI8 imageData;
    int64_t imageId = -1;
    int64_t movingPhotoId = -1;
    bool videoFile = false;
};

struct ExtraInfo {
    FetchOptionType fetchOptType;
    std::string networkId;
    std::string uri;
};
}

struct PickerCallBack {
    bool ready = false;
    bool isOrigin;
    int32_t resultCode;
    std::vector<std::string> uris;
};

char *MallocCString(const std::string &origin);
bool GetPredicate(COptions options, DataShare::DataSharePredicates &predicates,
    std::vector<std::string> &fetchColumn, ExtraInfo &extraInfo, int32_t &errCode);
void GetFetchOption(COptions options, DataShare::DataSharePredicates &predicates,
    std::vector<std::string> &fetchColumn, ExtraInfo &extraInfo, int32_t &errCode);
void AddDefaultAssetColumns(std::vector<std::string> &fetchColumn,
    std::function<bool(const std::string &columnName)> isValidColumn, NapiAssetType assetType,
    int32_t &errCode, const PhotoAlbumSubType subType = PhotoAlbumSubType::USER_GENERIC);
}
}
#endif