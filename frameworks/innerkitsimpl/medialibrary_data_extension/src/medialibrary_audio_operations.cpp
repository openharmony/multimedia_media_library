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

#include "medialibrary_audio_operations.h"

#include "abs_shared_result_set.h"
#include "medialibrary_command.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
int32_t MediaLibraryAudioOperations::Create(MediaLibraryCommand &cmd)
{
    return 0;
}

int32_t MediaLibraryAudioOperations::Delete(MediaLibraryCommand& cmd)
{
    return 0;
}

std::shared_ptr<NativeRdb::ResultSet> MediaLibraryAudioOperations::Query(
    MediaLibraryCommand &cmd, const vector<string> &columns)
{
    return nullptr;
}

int32_t MediaLibraryAudioOperations::Update(MediaLibraryCommand &cmd)
{
    return 0;
}

int32_t MediaLibraryAudioOperations::Open(MediaLibraryCommand &cmd, const string &mode)
{
    return 0;
}

int32_t MediaLibraryAudioOperations::Close(MediaLibraryCommand &cmd)
{
    return 0;
}
} // namespace Media
} // namespace OHOS