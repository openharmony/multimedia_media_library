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

#include <dirent.h>
#include <unistd.h>

#include "media_library.h"
#include "media_log.h"

using namespace std;
using namespace OHOS::Media;

namespace MediaLibTest {
    const int32_t SECOND_ARG_IDX = 2;
}

class MediaLibraryTest {
public:
    void TestGetAssets(const string &selection) const
    {
        unique_ptr<MediaLibrary> mediaLibrary = MediaLibrary::GetMediaLibraryInstance();
        vector<string> selectionArgs;

        MEDIA_DEBUG_LOG("Media assets:");
        vector<unique_ptr<MediaAsset>> mediaAssets
                            = mediaLibrary->GetMediaAssets(selection, selectionArgs);
        for (size_t i = 0; i < mediaAssets.size(); i++) {
            MEDIA_DEBUG_LOG("%{public}s", mediaAssets[i]->uri_.c_str());
        }

        MEDIA_DEBUG_LOG("Audio assets:");
        vector<unique_ptr<AudioAsset>> audioAssets
                            = mediaLibrary->GetAudioAssets(selection, selectionArgs);
        for (size_t i = 0; i < audioAssets.size(); i++) {
            MEDIA_DEBUG_LOG("%{public}s", audioAssets[i]->uri_.c_str());
        }

        MEDIA_DEBUG_LOG("Video assets:");
        vector<unique_ptr<VideoAsset>> videoAssets
                            = mediaLibrary->GetVideoAssets(selection, selectionArgs);
        for (size_t i = 0; i < videoAssets.size(); i++) {
            MEDIA_DEBUG_LOG("%{public}s", videoAssets[i]->uri_.c_str());
        }

        MEDIA_DEBUG_LOG("Image assets:");
        vector<unique_ptr<ImageAsset>> imageAssets
                            = mediaLibrary->GetImageAssets(selection, selectionArgs);
        for (size_t i = 0; i < imageAssets.size(); i++) {
            auto asset = imageAssets[i];
            MEDIA_DEBUG_LOG("uri:%{public}s, type:%{public}s, added:%{public}lld, modified:%{public}lld",
                asset->uri_.c_str(), asset->mimeType_.c_str(), asset->dateAdded_, asset->dateModified_);
        }
    }

    void TestGetAlbums(const string &selection) const
    {
        unique_ptr<MediaLibrary> mediaLibrary = MediaLibrary::GetMediaLibraryInstance();
        vector<string> selectionArgs;
        int32_t requestType = (int32_t)MediaType::MEDIA_TYPE_VIDEO;
        vector<unique_ptr<AlbumAsset>> albumAssets
                        = mediaLibrary->GetAlbumAssets(selection, selectionArgs, requestType);
        for (size_t i = 0; i < albumAssets.size(); i++) {
            MEDIA_DEBUG_LOG("Album name:%{private}s", albumAssets[i]->albumName_.c_str());
            MEDIA_DEBUG_LOG("Image album assets:");
            for (size_t j = 0; j < albumAssets[i]->imageAssetList_.size(); j++) {
                auto asset = albumAssets[i]->imageAssetList_[j];
                MEDIA_DEBUG_LOG("uri:%{public}s, w:%{public}d, h:%{public}d, add:%{public}lld, mod:%{public}lld",
                    asset->uri_.c_str(), asset->width_, asset->height_, asset->dateAdded_, asset->dateModified_);
            }

            MEDIA_DEBUG_LOG("Video album assets:");
            for (size_t k = 0; k < albumAssets[i]->videoAssetList_.size(); k++) {
                auto asset = albumAssets[i]->videoAssetList_[k];
                MEDIA_DEBUG_LOG(
                    "uri:%{public}s, w-h:%{public}d-%{public}d, dur-add-mod:%{public}d-%{public}lld-%{public}lld",
                    asset->uri_.c_str(), asset->width_, asset->height_, asset->duration_, asset->dateAdded_,
                    asset->dateModified_);
            }
        }
    }

    void TestMediaLibAPI(const string &selection) const
    {
        MEDIA_INFO_LOG("TestMediaLibAPI start");
        TestGetAssets(selection);
        TestGetAlbums(selection);
        MEDIA_INFO_LOG("TestMediaLibAPI end");
    }
};

int32_t main(int32_t argc, const char *argv[])
{
    MEDIA_INFO_LOG("media lib test in");

    if (argv == nullptr) {
        MEDIA_ERR_LOG("argv is null");
        return 0;
    }

    MEDIA_DEBUG_LOG("argc=%d, argv[0]=%s", argc, argv[0]);
    string selection = "";
    if (argc == MediaLibTest::SECOND_ARG_IDX) {
        selection = argv[MediaLibTest::SECOND_ARG_IDX - 1];
    }
    MediaLibraryTest testObj;
    testObj.TestMediaLibAPI(selection);

    return 0;
}
