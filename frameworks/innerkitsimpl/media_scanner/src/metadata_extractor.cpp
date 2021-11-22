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

#include "metadata_extractor.h"

namespace OHOS {
namespace Media {
using namespace std;

int32_t MetadataExtractor::ConvertStringToInteger(const string &str)
{
    int32_t integer = 0;
    std::stringstream ss(str);
    ss >> integer;
    return integer;
}

int32_t MetadataExtractor::Extract(Metadata &fileMetadata, const string &uri)
{
    int32_t errCode = ERR_FAIL;
    string fileuri;
    std::shared_ptr<AVMetadataHelper> avMetadataHelper = nullptr;
    std::unordered_map<int32_t, std::string> metadataMap;

    if (fileMetadata.GetFileMediaType() == MEDIA_TYPE_IMAGE) {
        return ERR_SUCCESS;
    }

    avMetadataHelper = AVMetadataHelperFactory::CreateAVMetadataHelper();
    if (avMetadataHelper == nullptr) {
        return errCode;
    }

    string prefix = "file://";
    fileuri = prefix.append(uri);
    errCode = avMetadataHelper->SetSource(fileuri, AV_META_USAGE_META_ONLY);
    if (errCode == ERR_SUCCESS) {
        metadataMap = avMetadataHelper->ResolveMetadata();
        if (!metadataMap.empty()) {
            string strTemp;
            int32_t intTempMeta;

            strTemp = metadataMap.at(AV_KEY_ALBUM);
            fileMetadata.SetAlbum(strTemp);

            strTemp = metadataMap.at(AV_KEY_ARTIST);
            fileMetadata.SetFileArtist(strTemp);

            strTemp = metadataMap.at(AV_KEY_DURATION);
            intTempMeta = ConvertStringToInteger(strTemp);
            fileMetadata.SetFileDuration(intTempMeta);

            strTemp = metadataMap.at(AV_KEY_TITLE);
            fileMetadata.SetFileTitle(strTemp);

            strTemp = metadataMap.at(AV_KEY_VIDEO_HEIGHT);
            intTempMeta = ConvertStringToInteger(strTemp);
            fileMetadata.SetFileHeight(intTempMeta);

            strTemp = metadataMap.at(AV_KEY_VIDEO_WIDTH);
            intTempMeta = ConvertStringToInteger(strTemp);
            fileMetadata.SetFileWidth(intTempMeta);

            strTemp = metadataMap.at(AV_KEY_MIME_TYPE);
            fileMetadata.SetFileMimeType(strTemp);
        }
    }

    avMetadataHelper->Release();
    return ERR_SUCCESS;
}
} // namespace Media
} // namespace OHOS
