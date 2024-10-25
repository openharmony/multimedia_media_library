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
#include <memory>
#include <stdio.h>

extern "C" void DebugPrintf(const char* fmt, ...);

#define MEDIA_DEBUG_LOG(fmt, ...) DebugPrintf(fmt"\n", ##__VA_ARGS__)
#define MEDIA_ERR_LOG(fmt, ...) DebugPrintf(fmt"\n", ##__VA_ARGS__)
#define MEDIA_WARNING_LOG(fmt, ...) DebugPrintf(fmt"\n", ##__VA_ARGS__)
#define MEDIA_INFO_LOG(fmt, ...) DebugPrintf(fmt"\n", ##__VA_ARGS__)
#define MEDIA_FATAL_LOG(fmt, ...) DebugPrintf(fmt"\n", ##__VA_ARGS__)

#define MEDIA_OK 0
#define MEDIA_INVALID_PARAM (-1)
#define MEDIA_INIT_FAIL (-2)
#define MEDIA_ERR (-3)
#define MEDIA_PERMISSION_DENIED (-4)

#endif // OHOS_MEDIA_LOG_H