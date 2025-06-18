/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef MEDIALIBRARY_AUDIO_OPERATIONS_H
#define MEDIALIBRARY_AUDIO_OPERATIONS_H

#include <memory>
#include <string>
#include <vector>

#include "abs_shared_result_set.h"
#include "medialibrary_asset_operations.h"
#include "medialibrary_command.h"


namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
class MediaLibraryAudioOperations : public MediaLibraryAssetOperations {
public:
    EXPORT static int32_t Create(MediaLibraryCommand &cmd);
    EXPORT static std::shared_ptr<NativeRdb::ResultSet> Query(MediaLibraryCommand &cmd,
        const std::vector<std::string> &columns);
    EXPORT static int32_t Update(MediaLibraryCommand &cmd);
    EXPORT static int32_t Delete(MediaLibraryCommand &cmd);
    EXPORT static int32_t Open(MediaLibraryCommand &cmd, const std::string &mode);
    EXPORT static int32_t Close(MediaLibraryCommand &cmd);
    EXPORT static void MoveToMusic();
    EXPORT static int32_t TrashAging(std::shared_ptr<int> countPtr = nullptr);

private:
    static int32_t CreateV9(MediaLibraryCommand &cmd);
    static int32_t CreateV10(MediaLibraryCommand &cmd);
    static int32_t DeleteAudio(const std::shared_ptr<FileAsset> &fileAsset, MediaLibraryApi api);
    static int32_t UpdateV9(MediaLibraryCommand &cmd);
    static int32_t UpdateV10(MediaLibraryCommand &cmd);
};
} // namespace Media
} // namespace OHOS

#endif // MEDIALIBRARY_AUDIO_OPERATIONS_H