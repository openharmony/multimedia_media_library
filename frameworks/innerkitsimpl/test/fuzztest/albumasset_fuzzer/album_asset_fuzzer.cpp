/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <cstdio>
#include <string>
#include <cstdint>

#include "album_asset_fuzzer.h"
#include "album_asset.h"

namespace OHOS {
namespace MediaLibrary {

using namespace Media;

bool ModifyAlbumAssetFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || size <= 0) {
        return false;
    }

    std::string albumUri(reinterpret_cast<const char*>(data), size);
    AlbumAsset albumAsset;
    bool errCode = albumAsset.ModifyAlbumAsset(albumUri);
    if (!errCode) {
        return true;
    }

    return false;
}

bool DeleteAlbumAssetFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || size <= 0) {
        return false;
    }

    std::string albumUri = std::string(reinterpret_cast<const char*>(data), size);
    if (albumUri.find("../") != std::string::npos) {
        return false;
    }

    std::string uri = std::string("/data/test/fuzzTest/") + std::string(albumUri);
    AlbumAsset albumAsset;
    bool errCode = albumAsset.DeleteAlbumAsset(uri);
    if (!errCode) {
        return true;
    }

    return false;
}

} // namespace MediaLibrary
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::MediaLibrary::ModifyAlbumAssetFuzzTest(data, size);
    OHOS::MediaLibrary::DeleteAlbumAssetFuzzTest(data, size);
    return 0;
}