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
#ifndef VIDEO_MODE_OPERATION_H
#define VIDEO_MODE_OPERATION_H
 
#include <cstdint>
#include <string>

#include "medialibrary_unistore_manager.h"
namespace OHOS::Media {
 
class PhotoVideoModeOperation {
public:
    static int32_t UpdatePhotosVideoMode(std::shared_ptr<MediaLibraryRdbStore> &rdbStore, const int32_t videoMode,
                                         const int32_t fileId);
    static int32_t BatchUpdatePhotosVideoMode(std::shared_ptr<MediaLibraryRdbStore> &rdbStore,
                                              const std::vector<std::string> &logFileIds);
    static int32_t GetMaxFileId(std::shared_ptr<MediaLibraryRdbStore> &rdbStore);
};
}  // namespace OHOS::Media
#endif // VIDEO_MODE_OPERATION_H