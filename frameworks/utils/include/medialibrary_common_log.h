/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIALIBRARY_COMMON_LOG_H
#define OHOS_MEDIALIBRARY_COMMON_LOG_H

#include "hilog/log.h"

#ifndef C_MLOG_TAG
#define C_MLOG_TAG "Common"
#endif

#undef C_LOG_DOMAIN
#define C_LOG_DOMAIN 0xD002B70

#undef C_LOG_TAG
#define C_LOG_TAG "MediaLibraryCommon"

#ifndef C_LOG_LABEL
#define C_LOG_LABEL { LOG_CORE, C_LOG_DOMAIN, C_LOG_TAG }
#endif

#define COMMON_HILOG(op, fmt, args...) \
    do { \
        op(C_LOG_LABEL, C_MLOG_TAG ":{%{public}s:%{public}d} " fmt, __FUNCTION__, __LINE__, ##args); \
    } while (0)

#define COMMON_DEBUG_LOG(fmt, ...) COMMON_HILOG(OHOS::HiviewDFX::HiLog::Debug, fmt, ##__VA_ARGS__)
#define COMMON_ERR_LOG(fmt, ...) COMMON_HILOG(OHOS::HiviewDFX::HiLog::Error, fmt, ##__VA_ARGS__)
#define COMMON_WARN_LOG(fmt, ...) COMMON_HILOG(OHOS::HiviewDFX::HiLog::Warn, fmt, ##__VA_ARGS__)
#define COMMON_INFO_LOG(fmt, ...) COMMON_HILOG(OHOS::HiviewDFX::HiLog::Info, fmt, ##__VA_ARGS__)
#define COMMON_FATAL_LOG(fmt, ...) COMMON_HILOG(OHOS::HiviewDFX::HiLog::Fatal, fmt, ##__VA_ARGS__)

#define CHECK_AND_ERR_LOG(cond, fmt, ...) \
    do { \
        if (!(cond)) { \
            COMMON_ERR_LOG(fmt, ##__VA_ARGS__); \
        } \
    } while (0)

#endif // OHOS_MEDIALIBRARY_COMMON_LOG_H
