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

constexpr int32_t RDB_OK = 0;
constexpr int32_t RDB_ERROR = -1;
constexpr int32_t RDB_ROW_OUT_RANGE = 1;
constexpr int32_t COLUMN_INDEX_FILE_ID = 0;
constexpr int32_t COLUMN_INDEX_PATH = 1;
constexpr int32_t COLUMN_INDEX_STORAGE_PATH = 2;
constexpr int32_t COLUMN_INDEX_FILE_SOURCE_TYPE = 3;
constexpr int32_t MOCK_RESULT_SET_COLUMN_COUNT = 4;

class MockDataShareResultSetForHandler : public DataShare::DataShareResultSet {
public:
    int GoToFirstRow() override
    {
        return RDB_OK;
    }

    int GoToNextRow() override
    {
        if (!hasReturned_) {
            hasReturned_ = true;
            return RDB_OK;
        }
        return RDB_ROW_OUT_RANGE;
    }

    int GetRowCount(int &count) override
    {
        count = 1;
        return RDB_OK;
    }

int GetString(int index, std::string &value) override
{
    if (index == COLUMN_INDEX_FILE_ID) {
        value = fileId_;
        return RDB_OK;
    }
    if (index == COLUMN_INDEX_PATH) {
        value = path_;
        return RDB_OK;
    }
    if (index == COLUMN_INDEX_STORAGE_PATH) {
        value = storagePath_;
        return RDB_OK;
    }
    return RDB_ERROR;
}

int GetInt(int index, int &value) override
{
    if (index == COLUMN_INDEX_FILE_SOURCE_TYPE) {
        value = fileSourceType_;
        return RDB_OK;
    }
    return RDB_ERROR;
}

int GetColumnCount(int &count) override
{
    count = MOCK_RESULT_SET_COLUMN_COUNT;
    return RDB_OK;
}

    int GetColumnIndex(const std::string &name, int &index) override
    {
        index = 0;
        return RDB_OK;
    }

    int GetColumnName(int index, std::string &name) override
    {
        name = "col" + std::to_string(index);
        return RDB_OK;
    }

    int GetLong(int index, int64_t &value) override
    {
        value = 0;
        return index >= 0 ? RDB_OK : RDB_ERROR;
    }

    int GetDouble(int index, double &value) override
    {
        value = 0.0;
        return index >= 0 ? RDB_OK : RDB_ERROR;
    }

    int GetBlob(int index, std::vector<uint8_t> &value) override
    {
        value.clear();
        return index >= 0 ? RDB_OK : RDB_ERROR;
    }

    int GetRowIndex(int &position) const override
    {
        position = hasReturned_ ? 0 : -1;
        return RDB_OK;
    }

    int IsAtFirstRow(bool &result) const override
    {
        result = hasReturned_;
        return RDB_OK;
    }

    int IsAtLastRow(bool &result) override
    {
        result = hasReturned_;
        return RDB_OK;
    }

    int IsStarted(bool &result) const override
    {
        result = hasReturned_;
        return RDB_OK;
    }

    int IsEnded(bool &result) override
    {
        result = hasReturned_;
        return RDB_OK;
    }

    int GetAllColumnNames(std::vector<std::string> &columnNames) override
    {
        columnNames = { "id", "path", "storage_path", "file_source_type" };
        return RDB_OK;
    }

    int GoToPreviousRow() override { return RDB_OK; }
    int GoToRow(int position) override { return position >= 0 ? RDB_OK : RDB_ERROR; }
    int Close() override { return RDB_OK; }
    bool IsClosed() const override { return false; }
    int GoTo(int offset) override { return offset >= 0 ? RDB_OK : RDB_ERROR; }
    int GoToLastRow() override { return RDB_OK; }

    std::string fileId_ = "123";
    std::string path_ = "/storage/cloud/files/Photo/1/test.jpg";
    std::string storagePath_ = "/storage/media/local/files/Docs/Download/test.jpg";
    int32_t fileSourceType_ = 1;
    bool hasReturned_ = false;
};

void MediaLibraryHandlerTest::SetUpTestCase(void) {}

void MediaLibraryHandlerTest::TearDownTestCase(void) {}

// SetUp:Execute before each test case
void MediaLibraryHandlerTest::SetUp(void) {}

void MediaLibraryHandlerTest::TearDown(void) {}

/**
 * @tc.number    : MediaLibraryHandler_test_001
 * @tc.name      : convert file uri
 * @tc.desc      : convert file uri to mnt path
 */
HWTEST_F(MediaLibraryHandlerTest, MediaLibraryHandler_test_001, TestSize.Level1)
{
    vector<string> uris;
    vector<string> results;
    results.push_back("10001");
    ConvertFileUriToMntPath(uris, results);
    EXPECT_EQ(results.empty(), true);

    uris.push_back("file://media/Photo/adc.png");
    ConvertFileUriToMntPath(uris, results);
    EXPECT_TRUE(results.empty());

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
HWTEST_F(MediaLibraryHandlerTest, MediaLibraryHandler_test_002, TestSize.Level1)
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
HWTEST_F(MediaLibraryHandlerTest, MediaLibraryHandler_test_003, TestSize.Level1)
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
 * @tc.number    : MediaLibraryHandler_test_004
 * @tc.name      : convert file uri
 * @tc.desc      : convert file uri to mnt path
 */
HWTEST_F(MediaLibraryHandlerTest, MediaLibraryHandler_test_004, TestSize.Level1)
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


/**
 * @tc.number    : MediaLibraryHandler_test_005
 * @tc.name      : convert file uri
 * @tc.desc      : convert file uri to mnt path
 */
HWTEST_F(MediaLibraryHandlerTest, MediaLibraryHandler_test_005, TestSize.Level1)
{
    auto mediaLibraryHandlerManager = MediaLibraryHandler::GetMediaLibraryHandler();

    vector<string> uris;
    vector<string> results;

    mediaLibraryHandlerManager->GetDataUris(uris, results);

    uris.push_back("media://photo123");
    mediaLibraryHandlerManager->GetDataUris(uris, results);
    EXPECT_TRUE(results.empty());

    mediaLibraryHandlerManager->userId_ = -1; // ReCreate
    mediaLibraryHandlerManager->InitMediaLibraryHandler();

    uris.push_back("file://test");
    mediaLibraryHandlerManager->GetDataUris(uris, results);
    EXPECT_TRUE(results.empty());

    mediaLibraryHandlerManager->sDataShareHelper_ = nullptr;  // ReCreate
    mediaLibraryHandlerManager->InitMediaLibraryHandler();
    uris.push_back("media://photo/abc");
    mediaLibraryHandlerManager->GetDataUris(uris, results);
    EXPECT_TRUE(results.empty());
}

#if defined(MEDIALIBRARY_FILE_MGR_SUPPORT) || defined(MEDIALIBRARY_LAKE_SUPPORT)
/**
 * @tc.number    : MediaLibraryHandler_file_manager_test_001
 * @tc.name      : process result set for file manager source
 * @tc.desc      : verify file manager source path branch in ProcessResultSet
 */
HWTEST_F(MediaLibraryHandlerTest, MediaLibraryHandler_file_manager_test_001, TestSize.Level1)
{
    auto mediaLibraryHandlerManager = MediaLibraryHandler::GetMediaLibraryHandler();
    std::shared_ptr<DataShare::DataShareResultSet> resultSet = make_shared<MockDataShareResultSetForHandler>();
    vector<string> dataUris;
    vector<string> fileIds = { "123" };
    int32_t ret = mediaLibraryHandlerManager->ProcessResultSet(resultSet, dataUris, fileIds);
    EXPECT_EQ(ret, RDB_OK);
    ASSERT_EQ(dataUris.size(), 1);
    EXPECT_TRUE(dataUris[0].find("/storage/media/") == 0);
    EXPECT_TRUE(dataUris[0].find("/local/files/Docs/Download/test.jpg") != std::string::npos);
    EXPECT_TRUE(dataUris[0].find("/cloud/files/Photo/1/test.jpg") == std::string::npos);
}
#endif
} // namespace Media
} // namespace OHOS
