/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#define MLOG_TAG "ActiveAnalysisErrorUtils"

#include "active_analysis_error_utils.h"

#include <string>

#include "media_library_error_code.h"
#include "medialibrary_client_errno.h"

namespace OHOS::Media {
namespace {
constexpr int32_t ACTIVE_ANALYSIS_SERVICE_SUCCESS = 0;
constexpr int32_t ACTIVE_ANALYSIS_SERVICE_TASK_ABNORMAL = 3;
constexpr int32_t ACTIVE_ANALYSIS_SERVICE_GET_FILE_ID_FAIL = 4;
constexpr int32_t ACTIVE_ANALYSIS_SERVICE_DESCRIPTOR_NOT_MATCHED = 5;
constexpr int32_t ACTIVE_ANALYSIS_SERVICE_TASK_CODE_ERROR = 6;
constexpr int32_t ACTIVE_ANALYSIS_SERVICE_TASK_RUNNING_CONFLICT = 7;
constexpr int32_t ACTIVE_ANALYSIS_SERVICE_TASK_TIMEOUT = 99;
} // namespace

int32_t NormalizeActiveAnalysisErrorCode(int32_t code)
{
    switch (code) {
        case ACTIVE_ANALYSIS_SERVICE_SUCCESS:
            return E_OK;
        case ACTIVE_ANALYSIS_SERVICE_TASK_CODE_ERROR:
            return MEDIA_LIBRARY_INVALID_PARAMETER_ERROR;
        case ACTIVE_ANALYSIS_SERVICE_TASK_RUNNING_CONFLICT:
            return MEDIA_LIBRARY_ACTIVE_ANALYSIS_ALREADY_RUNNING_ERROR;
        case E_PERMISSION_DENIED:
        case E_CHECK_SYSTEMAPP_FAIL:
        case MEDIA_LIBRARY_ACTIVE_ANALYSIS_HIGH_TEMPERATURE_ERROR:
        case MEDIA_LIBRARY_ACTIVE_ANALYSIS_LOW_BATTERY_ERROR:
        case MEDIA_LIBRARY_ACTIVE_ANALYSIS_LOW_STORAGE_ERROR:
        case MEDIA_LIBRARY_ACTIVE_ANALYSIS_POWER_SAVE_MODE_ERROR:
        case MEDIA_LIBRARY_ACTIVE_ANALYSIS_SWITCH_DISABLED_ERROR:
        case MEDIA_LIBRARY_ACTIVE_ANALYSIS_ALREADY_RUNNING_ERROR:
        case MEDIA_LIBRARY_ACTIVE_ANALYSIS_OTHER_ERROR:
        case MEDIA_LIBRARY_INVALID_PARAMETER_ERROR:
        case MEDIA_LIBRARY_INTERNAL_SYSTEM_ERROR:
            return code;
        case ACTIVE_ANALYSIS_SERVICE_TASK_ABNORMAL:
        case ACTIVE_ANALYSIS_SERVICE_GET_FILE_ID_FAIL:
        case ACTIVE_ANALYSIS_SERVICE_DESCRIPTOR_NOT_MATCHED:
        case ACTIVE_ANALYSIS_SERVICE_TASK_TIMEOUT:
        default:
            return MEDIA_LIBRARY_INTERNAL_SYSTEM_ERROR;
    }
}
} // namespace OHOS::Media
