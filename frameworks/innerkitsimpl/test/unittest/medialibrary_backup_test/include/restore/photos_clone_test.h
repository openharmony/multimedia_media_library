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

#ifndef OHOS_MEDIA_PHOTOS_CLONE_TEST_H
#define OHOS_MEDIA_PHOTOS_CLONE_TEST_H

#include <string>

#include "gtest/gtest.h"

namespace OHOS::Media {
class PhotosCloneTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

class PhotosCloneTestUtils {
public:
    static void ClearAllData();
    static void ClearPhotosData();
    static void ClearPhotoAlbumData();
    static void InsertPhoto(const std::string &cloudId = "");
    static void InsertAlbum();
};
}  // namespace OHOS::Media
#endif  // OHOS_MEDIA_PHOTOS_CLONE_TEST_H