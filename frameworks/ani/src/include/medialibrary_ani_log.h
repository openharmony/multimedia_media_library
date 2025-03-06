/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_ANI_SRC_INCLUDE_MEDIALIBRARY_ANI_LOG_H
#define FRAMEWORKS_ANI_SRC_INCLUDE_MEDIALIBRARY_ANI_LOG_H

#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002B71

#ifndef MLOG_TAG
#define MLOG_TAG "Common"
#endif

#undef LOG_TAG
#define LOG_TAG "MediaLibraryAni"

#ifndef LOG_LABEL
#define LOG_LABEL { LOG_CORE, LOG_DOMAIN, LOG_TAG }
#endif

#include "hilog/log.h"

#define FILE_NAME (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)

#define ANI_HILOG(op, type, fmt, args...) \
    do {                                  \
        op(LOG_CORE, type, LOG_DOMAIN, LOG_TAG, MLOG_TAG ":{%{public}s:%{public}d} " fmt, __FUNCTION__, __LINE__, \
            ##args);  \
    } while (0)

#define ANI_DEBUG_LOG(fmt, ...) ANI_HILOG(HILOG_IMPL, LOG_DEBUG, fmt, ##__VA_ARGS__)
#define ANI_ERR_LOG(fmt, ...) ANI_HILOG(HILOG_IMPL, LOG_ERROR, fmt, ##__VA_ARGS__)
#define ANI_WARN_LOG(fmt, ...) ANI_HILOG(HILOG_IMPL, LOG_WARN, fmt, ##__VA_ARGS__)
#define ANI_INFO_LOG(fmt, ...) ANI_HILOG(HILOG_IMPL, LOG_INFO, fmt, ##__VA_ARGS__)
#define ANI_FATAL_LOG(fmt, ...) ANI_HILOG(HILOG_IMPL, LOG_FATAL, fmt, ##__VA_ARGS__)

#define ANI_CHECK_RETURN_RET_LOG(cond, ret, fmt, ...)       \
    do {                                                    \
        if (!(cond)) {                                      \
            ANI_ERR_LOG(fmt, ##__VA_ARGS__);                \
            return ret;                                     \
        }                                                   \
    } while (0)

#define ANI_CHECK_RETURN_LOG(cond, fmt, ...)                \
    do {                                                    \
        if (!(cond)) {                                      \
            ANI_ERR_LOG(fmt, ##__VA_ARGS__);                \
            return;                                         \
        }                                                   \
    } while (0)

#define ANI_CHECK_PRINT_LOG(cond, fmt, ...)                 \
    do {                                                    \
        if (!(cond)) {                                      \
            ANI_ERR_LOG(fmt, ##__VA_ARGS__);                \
        }                                                   \
    } while (0)

#define ANI_CHECK_WARN_LOG(cond, fmt, ...)                  \
    do {                                                    \
        if (!(cond)) {                                      \
            ANI_WARN_LOG(fmt, ##__VA_ARGS__);               \
        }                                                   \
    } while (0)

#define ANI_CHECK_RETURN_RET(cond, ret)                     \
    do {                                                    \
        if (!(cond)) {                                      \
            return ret;                                     \
        }                                                   \
    } while (0)

#endif // FRAMEWORKS_ANI_SRC_INCLUDE_MEDIALIBRARY_ANI_LOG_H