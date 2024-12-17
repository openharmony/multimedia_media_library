/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIA_PHOTO_ALBUM_DAO_TEST_H
#define OHOS_MEDIA_PHOTO_ALBUM_DAO_TEST_H

#include <sys/stat.h>
#include <sys/types.h>
#include <utime.h>

#include "gtest/gtest.h"
#include "ffrt.h"
#include "ffrt_inner.h"
#include "database_utils.h"
#include "photo_album_dao.h"

namespace OHOS::Media {
const std::string DB_PATH_MEDIALIBRARY = "/data/test/backup/db/medialibrary/ce/databases/rdb/media_library.db";
const std::string BASE_DIR_MEDIALIBRARY = "/data/test/backup/db/medialibrary/ce/databases";
class PhotoAlbumDaoTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

public:
    static void Init();
    void GetPhotoAlbum(const std::string &lPath, int32_t maxLoop)
    {
        while (maxLoop-- > 0) {
            this->photoAlbumDao_.GetPhotoAlbum(lPath);
        }
    }

    void GetOrCreatePhotoAlbum(const std::string &lPath)
    {
        auto albumData = this->photoAlbumDao_.BuildAlbumInfoByLPath(lPath);
        this->photoAlbumDao_.GetOrCreatePhotoAlbum(albumData);
    }

    void RunPhotoAlbumCache(const std::string &lPath)
    {
        int32_t maxReadRepeatTimes = 100;
        int32_t maxReadTimes = 10;
        int32_t maxWriteTimes = 100;
        for (int32_t offset = 0; offset < maxReadTimes; offset++) {
            ffrt::submit([this, lPath, maxReadRepeatTimes]() { GetPhotoAlbum(lPath, maxReadRepeatTimes); },
                {&lPath, &maxReadRepeatTimes},
                {},
                ffrt::task_attr().qos(static_cast<int32_t>(ffrt::qos_utility)));
        }
        for (int32_t offset = 0; offset < maxWriteTimes; offset++) {
            ffrt::submit([this, lPath]() { GetOrCreatePhotoAlbum(lPath); },
                {&lPath},
                {},
                ffrt::task_attr().qos(static_cast<int32_t>(ffrt::qos_utility)));
        }
        ffrt::wait();
    }

public:
    PhotoAlbumDao photoAlbumDao_;
};
}  // namespace OHOS::Media
#endif  // OHOS_MEDIA_PHOTO_ALBUM_DAO_TEST_H