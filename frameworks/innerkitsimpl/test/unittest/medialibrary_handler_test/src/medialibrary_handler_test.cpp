/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <regex>
#include "medialibrary_handler_test.h"
#include "media_library_handler.h"

using namespace std;
using namespace OHOS;
using namespace testing::ext;

/**
 * @FileName MediaLibraryHandlerTest
 * @Desc Media library handler function test
 *
 */
namespace OHOS {
namespace Media {

std::string ReadFileToString(const std::string &fileName)
{
    std::ifstream file(fileName);
    if (!file) {
        return "";
    }

    std::ostringstream oss;
    oss << file.rdbuf();
    return oss.str();
}

void MediaLibraryHandlerTest::SetUpTestCase(void)
{
}

void MediaLibraryHandlerTest::TearDownTestCase(void)
{
}

// SetUp:Execute before each test case
void MediaLibraryHandlerTest::SetUp(void) {}

void MediaLibraryHandlerTest::TearDown(void) {}

/**
 * @tc.number    : MediaLibraryHandler_test_001
 * @tc.name      : convert file uri
 * @tc.desc      : convert file uri to mnt path
 */
HWTEST_F(MediaLibraryHandlerTest, MediaLibraryHandler_test_001, TestSize.Level0)
{
    std::string filename = "/data/medialibrary_handler_unittest.txt";
    std::string fileContent = ReadFileToString(filename);
    ASSERT_TRUE(!fileContent.empty());

    vector<string> uris;
    vector<string> results;
    uris.push_back(fileContent);
    ConvertFileUriToMntPath(uris, results);
    EXPECT_TRUE(results.size() == uris.size());
    std::regex pattern("^/mnt/hmdfs/[0-9]+/account/cloud_merge_view/files/Photo/[0-9]+/.+$");
    EXPECT_TRUE(std::regex_match(results[0], pattern));

    uris.push_back(fileContent);
    ConvertFileUriToMntPath(uris, results);
    EXPECT_TRUE(results.size() == uris.size());

    uris.push_back("file://test");
    ConvertFileUriToMntPath(uris, results);
    EXPECT_TRUE(results.empty());

    uris[1] = "file://media/Photo/999/IMG_31313/IMG_e323123.png";
    ConvertFileUriToMntPath(uris, results);
    EXPECT_TRUE(results.empty());
}

/**
 * @tc.number    : MediaLibraryHandler_test_002
 * @tc.name      : convert file uri
 * @tc.desc      : convert file uri to mnt path
 */
HWTEST_F(MediaLibraryHandlerTest, MediaLibraryHandler_test_002, TestSize.Level0)
{
    auto mediaLibraryHandlerManager = MediaLibraryHandler::GetMediaLibraryHandler();

    vector<string> uris;
    vector<string> results;

    mediaLibraryHandlerManager->GetDataUris(uris, results);

    uris.push_back("media://photo123");
    mediaLibraryHandlerManager->GetDataUris(uris, results);
    EXPECT_TRUE(results.empty());

    mediaLibraryHandlerManager->InitMediaLibraryHandler();

    uris.push_back("file://test");
    mediaLibraryHandlerManager->GetDataUris(uris, results);
    EXPECT_TRUE(results.empty());

    uris.push_back("media://photo/abc");
    mediaLibraryHandlerManager->GetDataUris(uris, results);
    EXPECT_TRUE(results.empty());

    uris.push_back("media://photo/999");
    mediaLibraryHandlerManager->GetDataUris(uris, results);
    EXPECT_TRUE(results.empty());
    
    uris.push_back("");
    mediaLibraryHandlerManager->GetDataUris(uris, results);
    EXPECT_TRUE(results.empty());

    vector<string> uris_true;
    uris_true.push_back("media://photo/999");
    mediaLibraryHandlerManager->GetDataUris(uris_true, results);
    EXPECT_TRUE(results.empty());
}

/**
 * @tc.number    : MediaLibraryHandler_test_003
 * @tc.name      : convert file uri
 * @tc.desc      : convert file uri to mnt path
 */
HWTEST_F(MediaLibraryHandlerTest, MediaLibraryHandler_test_003, TestSize.Level0)
{
    auto mediaLibraryHandlerManager = MediaLibraryHandler::GetMediaLibraryHandler();

    auto resultSet = make_shared<DataShareResultSet>();
    int32_t row = 0;
    int32_t ret = mediaLibraryHandlerManager->CheckResultSet(resultSet, row);
    EXPECT_NE(ret, 0);

    row = 3;
    ret = mediaLibraryHandlerManager->CheckResultSet(resultSet, row);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.number    : MediaLibraryHandler_test_003
 * @tc.name      : convert file uri
 * @tc.desc      : convert file uri to mnt path
 */
HWTEST_F(MediaLibraryHandlerTest, MediaLibraryHandler_test_004, TestSize.Level0)
{
    auto mediaLibraryHandlerManager = MediaLibraryHandler::GetMediaLibraryHandler();

    auto resultSet = make_shared<DataShareResultSet>();
    vector<string> dataUris;
    vector<string> fileIds;
    int32_t ret = mediaLibraryHandlerManager->ProcessResultSet(resultSet, dataUris, fileIds);
    EXPECT_EQ(ret, -200);

    fileIds.push_back("media://photo/999");
    ret = mediaLibraryHandlerManager->ProcessResultSet(resultSet, dataUris, fileIds);
    EXPECT_EQ(ret, -200);

    fileIds.push_back("123");
    ret = mediaLibraryHandlerManager->ProcessResultSet(resultSet, dataUris, fileIds);
    EXPECT_EQ(ret, -200);
}
} // namespace Media
} // namespace OHOS
