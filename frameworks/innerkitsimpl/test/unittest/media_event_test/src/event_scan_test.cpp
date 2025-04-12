/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#define MLOG_TAG "EventScanTest"

#include "event_scan_test.h"

#include "medialibrary_errno.h"
#include "media_log.h"
#define private public
#include "media_scanner.h"
#include "media_scanner_db.h"
#undef private

using  namespace std;
using namespace OHOS;
using namespace testing::ext;

namespace OHOS {
namespace Media {

void EventScanTest::SetUpTestCase(void) {}

void EventScanTest::TearDownTestCase(void) {}

// SetUp:Execute before each test case
void EventScanTest::SetUp() {}

void EventScanTest::TearDown(void) {}

HWTEST_F(EventScanTest, medialib_event_ScanFileInternal_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("medialib_event_ScanFileInternal_test_001::start");
    string path = "medialib_ScanFileInternal_test_001/.test";
    shared_ptr<IMediaScannerCallback> callback = nullptr;
    MediaScannerObj mediaScannerObj(path, callback, MediaScannerObj::FILE);
    int32_t ret = mediaScannerObj.ScanFileInternal();
    EXPECT_EQ(ret, E_FILE_HIDDEN);
    MEDIA_INFO_LOG("medialib_event_ScanFileInternal_test_001::ret = %{public}d. End", ret);
}

HWTEST_F(EventScanTest, medialib_event_ScanFileInTraversal_test_001, TestSize.Level1)
{
    string dir = "/storage/cloud/files/";
    shared_ptr<IMediaScannerCallback> callback = nullptr;
    string parent = "ScanDirInternal";
    MediaScannerObj mediaScannerObj(dir, callback, MediaScannerObj::DIRECTORY);
    int32_t ret = mediaScannerObj.ScanFileInTraversal(dir, parent, UNKNOWN_ID);
    EXPECT_NE(ret, E_FILE_HIDDEN);

    string path = "medialib_event_ScanDirInternal_test_001/.test";
    string pathTest = "medialib_event_ScanDirInternal_test_001/test";
    ret = mediaScannerObj.ScanFileInTraversal(path, parent, UNKNOWN_ID);
    EXPECT_EQ(ret, E_FILE_HIDDEN);
}

HWTEST_F(EventScanTest, medialib_event_InsertOrUpdateAlbumInfo_test_001, TestSize.Level1)
{
    string dir = "/storage/cloud/files";
    shared_ptr<IMediaScannerCallback> callback = nullptr;
    MediaScannerObj mediaScannerObj(dir, callback, MediaScannerObj::DIRECTORY);
    int32_t parentId= -1;
    const string albumName = "InsertOrUpdateAlbumInfo";
    int32_t ret = mediaScannerObj.InsertOrUpdateAlbumInfo("", parentId, albumName);
    EXPECT_EQ(ret, UNKNOWN_ID);
}

HWTEST_F(EventScanTest, medialib_event_ReadAlbums_test_001, TestSize.Level1)
{
    MediaScannerDb mediaScannerDb;
    unordered_map<string, Metadata> albumMap_;
    string pathTest = "";
    int32_t ret = mediaScannerDb.ReadAlbums(pathTest, albumMap_);
    EXPECT_EQ(ret, E_INVALID_ARGUMENTS);
}

HWTEST_F(EventScanTest, medialib_event_GetFileDBUriFromPath_test_001, TestSize.Level1)
{
    MediaScannerDb mediaScannerDb;
    string path = "";
    string uri = mediaScannerDb.GetFileDBUriFromPath(path);
    EXPECT_EQ(uri, "");
}
}
}