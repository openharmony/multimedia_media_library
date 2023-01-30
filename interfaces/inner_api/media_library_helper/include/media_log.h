/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_LOG_H_
#define INTERFACES_INNERKITS_NATIVE_INCLUDE_MEDIA_LOG_H_

#ifndef M_MLOG_TAG
#define M_MLOG_TAG "Common"
#endif

#undef M_LOG_DOMAIN
#define M_LOG_DOMAIN 0xD002B70

#undef M_LOG_TAG
#define M_LOG_TAG "MediaLibrary"

#ifndef M_LOG_LABEL
#define M_LOG_LABEL { LOG_CORE, M_LOG_DOMAIN, M_LOG_TAG }
#endif

#include "hilog/log.h"

#define MEDIA_HILOG(op, fmt, args...) \
    do {                                  \
        op(M_LOG_LABEL, M_MLOG_TAG ":{%{public}s:%{public}d} " fmt, __FUNCTION__, __LINE__, ##args);  \
    } while (0)

#define MEDIA_DEBUG_LOG(fmt, ...) MEDIA_HILOG(OHOS::HiviewDFX::HiLog::Debug, fmt, ##__VA_ARGS__)
#define MEDIA_ERR_LOG(fmt, ...) MEDIA_HILOG(OHOS::HiviewDFX::HiLog::Error, fmt, ##__VA_ARGS__)
#define MEDIA_WARN_LOG(fmt, ...) MEDIA_HILOG(OHOS::HiviewDFX::HiLog::Warn, fmt, ##__VA_ARGS__)
#define MEDIA_INFO_LOG(fmt, ...) MEDIA_HILOG(OHOS::HiviewDFX::HiLog::Info, fmt, ##__VA_ARGS__)
#define MEDIA_FATAL_LOG(fmt, ...) MEDIA_HILOG(OHOS::HiviewDFX::HiLog::Fatal, fmt, ##__VA_ARGS__)

#define CHECK_AND_RETURN_RET_LOG(cond, ret, fmt, ...)  \
    do {                                               \
        if (!(cond)) {                                 \
            MEDIA_ERR_LOG(fmt, ##__VA_ARGS__);         \
            return ret;                                \
        }                                              \
    } while (0)

#define CHECK_AND_RETURN_LOG(cond, fmt, ...)           \
    do {                                               \
        if (!(cond)) {                                 \
            MEDIA_ERR_LOG(fmt, ##__VA_ARGS__);         \
            return;                                    \
        }                                              \
    } while (0)

#define CHECK_AND_PRINT_LOG(cond, fmt, ...)            \
    do {                                               \
        if (!(cond)) {                                 \
            MEDIA_ERR_LOG(fmt, ##__VA_ARGS__);         \
        }                                              \
    } while (0)

#define CHECK_AND_RETURN_RET(cond, ret)  \
    do {                                               \
        if (!(cond)) {                                 \
            return ret;                                \
        }                                              \
    } while (0)

#endif // OHOS_MEDIA_LOG_H
