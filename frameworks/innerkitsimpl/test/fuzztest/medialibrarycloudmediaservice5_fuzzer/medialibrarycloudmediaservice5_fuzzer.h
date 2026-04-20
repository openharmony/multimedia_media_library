/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef MEDIALIBRARY_CLOUD_MEDIA_SERVICE5_FUZZER_H
#define MEDIALIBRARY_CLOUD_MEDIA_SERVICE5_FUZZER_H

#define FUZZ_PROJECT_NAME "medialibrary_cloudmediaservice5_fuzzer"

#include "cloud_media_sync_const.h"

namespace OHOS::Media {
using namespace OHOS::Media::CloudSync;

const std::vector<ServerErrorCode> SERVER_ERROR_CODE_LIST = {
    ServerErrorCode::NETWORK_ERROR,
    ServerErrorCode::UID_EMPTY,
    ServerErrorCode::INVALID_LOCK_PARAM,
    ServerErrorCode::RESPONSE_TIME_OUT,
    ServerErrorCode::NO_NETWORK
};

const std::vector<ErrorType> ERROR_TYPE_LIST = {
    ErrorType::TYPE_UNKNOWN,
    ErrorType::TYPE_NOT_NEED_RETRY,
};

const std::vector<ErrorDetailCode> ERROR_DETAIL_CODE_LIST = {
    ErrorDetailCode::SPACE_FULL,
    ErrorDetailCode::BUSINESS_MODEL_CHANGE_DATA_UPLOAD_FORBIDDEN,
    ErrorDetailCode::SAME_FILENAME_NOT_ALLOWED,
    ErrorDetailCode::CONTENT_NOT_FIND,
    ErrorDetailCode::FILE_REFERENCED
};

const std::vector<int32_t> FILE_TYPE_LIST = {
    FILE_TYPE_IMAGE,
    FILE_TYPE_VIDEO,
    FILE_TYPE_LIVEPHOTO
};
} //namespace OHOS::Media
#endif
