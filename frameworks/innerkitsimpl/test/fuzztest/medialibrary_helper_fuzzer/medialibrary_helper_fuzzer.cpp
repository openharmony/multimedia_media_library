/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "medialibrary_helper_fuzzer.h"
#include "album_asset.h"
#include "media_file_utils.h"
#include "medialibrary_type_const.h"
#include "media_log.h"

using namespace OHOS;
using namespace OHOS::Media;

namespace OHOS {
namespace MediaLibraryHelper {

bool MediaLibraryHelperSetFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return false;
    }
    AlbumAsset albumAsset;
    const int32_t albumId = *(reinterpret_cast<const int32_t *>(data));
    const std::string albumName(reinterpret_cast<const char *>(data), size);
    const int64_t albumDateModified = *(reinterpret_cast<const int64_t *>(data));
    const std::string albumRelativePath(reinterpret_cast<const char *>(data), size);
    const std::string coverUri(reinterpret_cast<const char *>(data), size);
    const std::string albumPath(reinterpret_cast<const char *>(data), size);
    const bool albumVirtual = *(reinterpret_cast<const bool *>(data));
    ResultNapiType type = *(reinterpret_cast<const ResultNapiType*>(data));

    albumAsset.SetAlbumId(albumId);
    albumAsset.SetAlbumName(albumName);
    albumAsset.SetAlbumDateModified(albumDateModified);
    albumAsset.SetAlbumRelativePath(albumRelativePath);
    albumAsset.SetAlbumPath(albumPath);
    albumAsset.SetAlbumVirtual(albumVirtual);
    albumAsset.SetResultNapiType(type);
    return true;
}

bool MediaLibraryHelperGetFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return false;
    }
    AlbumAsset albumAsset;
    albumAsset.GetAlbumId();
    albumAsset.GetAlbumName();
    albumAsset.GetAlbumUri();
    albumAsset.GetAlbumDateModified();
    albumAsset.GetCount();
    albumAsset.GetAlbumRelativePath();
    albumAsset.GetCoverUri();
    albumAsset.GetAlbumPath();
    albumAsset.GetAlbumVirtual();
    albumAsset.CreateAlbumAsset();
    albumAsset.GetResultNapiType();
    return true;
}

} // namespace StorageManager
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::MediaLibraryHelper::MediaLibraryHelperSetFuzzTest(data, size);
    OHOS::MediaLibraryHelper::MediaLibraryHelperGetFuzzTest(data, size);
    return 0;
}
