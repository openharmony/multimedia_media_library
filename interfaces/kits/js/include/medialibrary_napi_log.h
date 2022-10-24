/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIALIBRARY_NAPI_LOG_H
#define OHOS_MEDIALIBRARY_NAPI_LOG_H

#undef N_LOG_DOMAIN
#define N_LOG_DOMAIN 0xD002B71

#ifndef N_MLOG_TAG
#define N_MLOG_TAG "Common"
#endif

#undef N_LOG_TAG
#define N_LOG_TAG "MediaLibraryNapi"

#ifndef N_LOG_LABEL
#define N_LOG_LABEL { LOG_CORE, N_LOG_DOMAIN, N_LOG_TAG }
#endif

#include "hilog/log.h"

#define __FILE_NAME__ (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)

#define NAPI_HILOG(op, fmt, args...) \
    do {                                  \
        op(N_LOG_LABEL, N_MLOG_TAG ":{%{public}s:%{public}d} " fmt, __FUNCTION__, __LINE__, ##args);  \
    } while (0)

#define NAPI_DEBUG_LOG(fmt, ...) NAPI_HILOG(OHOS::HiviewDFX::HiLog::Debug, fmt, ##__VA_ARGS__)
#define NAPI_ERR_LOG(fmt, ...) NAPI_HILOG(OHOS::HiviewDFX::HiLog::Error, fmt, ##__VA_ARGS__)
#define NAPI_WARN_LOG(fmt, ...) NAPI_HILOG(OHOS::HiviewDFX::HiLog::Warn, fmt, ##__VA_ARGS__)
#define NAPI_INFO_LOG(fmt, ...) NAPI_HILOG(OHOS::HiviewDFX::HiLog::Info, fmt, ##__VA_ARGS__)
#define NAPI_FATAL_LOG(fmt, ...) NAPI_HILOG(OHOS::HiviewDFX::HiLog::Fatal, fmt, ##__VA_ARGS__)

#endif // OHOS_MEDIALIBRARY_NAPI_LOG_H
