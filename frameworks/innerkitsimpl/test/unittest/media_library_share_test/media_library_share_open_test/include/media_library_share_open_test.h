/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef MEDIA_LIBRARY_SHARE_OPEN_TEST_H
#define MEDIA_LIBRARY_SHARE_OPEN_TEST_H

#include <gtest/gtest.h>
#include <mutex>

namespace OHOS {
namespace Media {

class MediaLibraryShareOpenTest : public testing::Test {
public:
    // input testsuit setup step，setup invoked before all testcases
    static void SetUpTestCase(void);
    // input testsuit teardown step，teardown invoked after all testcases
    static void TearDownTestCase(void);
    // input testcase setup step，setup invoked before each testcases
    void SetUp();
    // input testcase teardown step，teardown invoked after each testcases
    void TearDown();

    static void CheckTestFileExistence();
    static void InitMediaLibrary();
    static bool IsValid();
    static void ProcessPermission();
    static void CreateDataHelper(int32_t systemAbilityId);
    static int32_t CreatePhotoApi10(int mediaType, const std::string &displayName, bool isPhotoEdited = false,
        bool isMovingPhoto = false);
    static void InitTestFileAsset(const std::string &id, bool isEdited = false);
    static void InitEditedFiles(const std::string &assetPath);
    static void CopyToDestPath(int32_t srcFd, const std::string &destPath);
    static void InitPhotoAsset(std::string &dataFileUri, bool isEdited = false);
    static void InitEditedFiles();
private:
    static std::mutex Mutex_;
    static inline bool isValid_ = false;
};
}  // namespace Media
}  // namespace OHOS
#endif  // MEDIA_LIBRARY_SHARE_OPEN_TEST_H