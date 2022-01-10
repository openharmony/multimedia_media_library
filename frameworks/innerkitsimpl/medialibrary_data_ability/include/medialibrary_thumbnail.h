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

#ifndef MEDIA_THUMBNAIL_H
#define MEDIA_THUMBNAIL_H

#include "media_thumbnail_helper.h"
#include "rdb_helper.h"

namespace OHOS {
namespace Media {
static const Size DEFAULT_LCD_SIZE = {
    .width = 0,
    .height = 1080
};

struct ThumbRdbOpt {
    std::shared_ptr<NativeRdb::RdbStore> store;
    std::string table;
    std::string row;
};

struct ThumbnailData {
    std::string  id;
    std::string path;
    std::string thumbnailKey;
    std::string lcdKey;
    std::unique_ptr<PixelMap> source;
    std::vector<uint8_t> thumbnail;
    std::vector<uint8_t> lcd;
};

struct ThumbnailRdbData {
    std::string id;
    std::string path;
    std::string thumbnailKey;
    std::string lcdKey;
};

class MediaLibraryThumbnail : public MediaThumbnailHelper {
public:
    MediaLibraryThumbnail();
    ~MediaLibraryThumbnail() = default;

    bool CreateThumbnail(ThumbRdbOpt &opts, std::string &key);

    bool CreateLcd(ThumbRdbOpt &opts, std::string &key);

    void CreateThumbnails(ThumbRdbOpt &opts);

    std::string GetThumbnailKey(ThumbRdbOpt &opts, Size &size);
    std::unique_ptr<PixelMap> GetThumbnailByRdb(ThumbRdbOpt &opts, Size &size);

private:
    // utils
    bool LoadImageFile(std::string &path, std::unique_ptr<PixelMap> &pixelMap);
    bool GenKey(std::vector<uint8_t> &data, std::string &key);
    bool CompressImage(std::unique_ptr<PixelMap> &pixelMap, Size &size, std::vector<uint8_t> &data);

    // KV Store
    bool SaveImage(std::string &key, std::vector<uint8_t> &image);

    // RDB Store
    bool QueryThumbnailInfo(ThumbRdbOpt &opts, ThumbnailData &data, int &errorCode);
    bool QueryThumbnailInfos(ThumbRdbOpt &opts, std::vector<ThumbnailRdbData> &infos, int &errorCode);
    bool UpdateThumbnailInfo(ThumbRdbOpt &opts, ThumbnailData &data, int &errorCode);

    // Steps
    bool LoadSourceImage(ThumbnailData &data);
    bool GenThumbnailKey(ThumbnailData &data);
    bool GenLcdKey(ThumbnailData &data);
    bool CreateThumbnailData(ThumbnailData &data);
    bool CreateLcdData(ThumbnailData &data);
    bool SaveThumbnailData(ThumbnailData &data);
    bool SaveLcdData(ThumbnailData &data);

    bool GetThumbnailFromKvStore(ThumbnailData &data);
    bool GetLcdFromKvStore(ThumbnailData &data);
    bool ResizeThumbnailToTarget(ThumbnailData &data, Size &size, std::unique_ptr<PixelMap> &pixelMap);
    bool ResizeLcdToTarget(ThumbnailData &data, Size &size, std::unique_ptr<PixelMap> &pixelMap);

    bool CreateThumbnail(ThumbRdbOpt &opts, ThumbnailData &data, std::string &key);
};
} // namespace Media
} // namespace  OHOS
#endif  // MEDIA_THUMBNAIL_H
