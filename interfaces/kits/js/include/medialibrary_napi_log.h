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

#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002B71

#ifndef MLOG_TAG
#define MLOG_TAG "Common"
#endif

#undef LOG_TAG
#define LOG_TAG "MediaLibraryNapi"

#ifndef LOG_LABEL
#define LOG_LABEL { LOG_CORE, LOG_DOMAIN, LOG_TAG }
#endif

#include "hilog/log.h"

#define __FILE_NAME__ (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)

#define NAPI_HILOG(op, type, fmt, args...) \
    do {                                  \
        op(LOG_CORE, type, LOG_DOMAIN, LOG_TAG, MLOG_TAG ":{%{public}s:%{public}d} " fmt, __FUNCTION__, __LINE__, \
            ##args);  \
    } while (0)

#define NAPI_DEBUG_LOG(fmt, ...) NAPI_HILOG(HILOG_IMPL, LOG_DEBUG, fmt, ##__VA_ARGS__)
#define NAPI_ERR_LOG(fmt, ...) NAPI_HILOG(HILOG_IMPL, LOG_ERROR, fmt, ##__VA_ARGS__)
#define NAPI_WARN_LOG(fmt, ...) NAPI_HILOG(HILOG_IMPL, LOG_WARN, fmt, ##__VA_ARGS__)
#define NAPI_INFO_LOG(fmt, ...) NAPI_HILOG(HILOG_IMPL, LOG_INFO, fmt, ##__VA_ARGS__)
#define NAPI_FATAL_LOG(fmt, ...) NAPI_HILOG(HILOG_IMPL, LOG_FATAL, fmt, ##__VA_ARGS__)

#endif // OHOS_MEDIALIBRARY_NAPI_LOG_H
