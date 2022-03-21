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
#include "media_log.h"

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

int32_t MetadataExtractor::ExtractImageMetadata(Metadata &fileMetadata)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/" + fileMetadata.GetFileExtension();
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(fileMetadata.GetFilePath(), opts, errorCode);
    if (errorCode != ERR_SUCCESS || imageSource == nullptr) {
        MEDIA_ERR_LOG("Failed to obtain image source");
        return ERR_SUCCESS;
    }

    ImageInfo imageInfo;
    uint32_t ret = imageSource->GetImageInfo(0, imageInfo);
    if (ret == ERR_SUCCESS) {
        fileMetadata.SetFileWidth(imageInfo.size.width);
        fileMetadata.SetFileHeight(imageInfo.size.height);
    }

    return ERR_SUCCESS;
}
int32_t MetadataExtractor::Extract(Metadata &fileMetadata, const string &uri)
{
    int32_t errCode = ERR_FAIL;
    string fileuri;
    std::shared_ptr<AVMetadataHelper> avMetadataHelper = nullptr;
    std::unordered_map<int32_t, std::string> metadataMap;

    // If the file type is not audio/video/image
    auto mimeType = ScannerUtils::GetMimeTypeFromExtension(fileMetadata.GetFileExtension());
    fileMetadata.SetFileMimeType(mimeType);
    auto isSupported = std::find(EXTRACTOR_SUPPORTED_MIME.begin(), EXTRACTOR_SUPPORTED_MIME.end(), mimeType) !=
        EXTRACTOR_SUPPORTED_MIME.end();
    if (!isSupported) {
        MEDIA_ERR_LOG("Mime type is not supported by the extractor");
        return ERR_SUCCESS;
    }

    if (fileMetadata.GetFileMediaType() == MEDIA_TYPE_IMAGE) {
        return ExtractImageMetadata(fileMetadata);
    }

    avMetadataHelper = AVMetadataHelperFactory::CreateAVMetadataHelper();
    if (avMetadataHelper == nullptr) {
        MEDIA_ERR_LOG("AV metadata helper is null");
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
