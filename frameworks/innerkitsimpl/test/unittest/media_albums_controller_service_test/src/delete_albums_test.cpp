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

#define MLOG_TAG "DeleteAlbumsTest"

#include "delete_albums_test.h"

#include <memory>
#include <string>

#define private public
#define protected public
#include "media_albums_controller_service.h"
#undef private
#undef protected

#include "delete_albums_vo.h"
#include "user_define_ipc_client.h"
#include "medialibrary_album_operations.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unittest_utils.h"
#include "medialibrary_unistore_manager.h"

namespace OHOS::Media {
using namespace std;
using namespace testing::ext;
using namespace OHOS::NativeRdb;

static shared_ptr<MediaLibraryRdbStore> g_rdbStore;
static constexpr int32_t SLEEP_SECONDS = 1;

int32_t ClearAlbums()
{
    RdbPredicates predicates(PhotoAlbumColumns::TABLE);

    int32_t rows = 0;
    int32_t err = g_rdbStore->Delete(rows, predicates);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to clear album table, err: %{public}d", err);
        return E_HAS_DB_ERROR;
    }
    return E_OK;
}

void DeleteAlbumsTest::SetUpTestCase(void)
{
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("Start MediaLibraryPhotoOperationsTest failed, can not get g_rdbStore");
        exit(1);
    }
    ClearAlbums();
    MEDIA_INFO_LOG("SetUpTestCase");
}

void DeleteAlbumsTest::TearDownTestCase(void)
{
    ClearAlbums();
    MEDIA_INFO_LOG("TearDownTestCase");
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_SECONDS));
}

void DeleteAlbumsTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
}

void DeleteAlbumsTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

inline int32_t CreatePhotoAlbum(const string &albumName)
{
    NativeRdb::ValuesBucket value;
    value.PutString(PhotoAlbumColumns::ALBUM_NAME, albumName);
    MediaLibraryCommand cmd(OperationObject::PHOTO_ALBUM, OperationType::CREATE, value);
    return MediaLibraryAlbumOperations::HandlePhotoAlbumOperations(cmd);
}

HWTEST_F(DeleteAlbumsTest, DeleteAlbums_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("DeleteAlbums_Test_001 enter");

    DeleteAlbumsReqBody reqBody;
    MessageParcel data;
    auto ret = reqBody.Marshalling(data);
    EXPECT_EQ(ret, true);

    MessageParcel reply;
    MediaAlbumsControllerService controller;
    controller.DeletePhotoAlbums(data, reply);

    IPC::MediaRespVo<IPC::MediaEmptyObjVo> respVo;
    ret = respVo.Unmarshalling(reply);
    EXPECT_EQ(ret, true);

    auto deleteRows = respVo.GetErrCode();
    EXPECT_EQ(deleteRows, -EINVAL);

    MEDIA_INFO_LOG("DeleteAlbums_Test_001 end");
}

HWTEST_F(DeleteAlbumsTest, DeleteAlbums_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("DeleteAlbums_Test_002 enter");

    const vector<string> albumNames = {
        "DeleteAlbums_Test_001_001",
        "DeleteAlbums_Test_001_002",
        "DeleteAlbums_Test_001_003",
        "DeleteAlbums_Test_001_004",
        "DeleteAlbums_Test_001_005",
    };

    DeleteAlbumsReqBody reqBody;
    for (const auto &albumName : albumNames) {
        int32_t albumId = CreatePhotoAlbum(albumName);
        ASSERT_GT(albumId, 0);
        reqBody.albumIds.push_back(to_string(albumId));
    }

    MessageParcel data;
    auto ret = reqBody.Marshalling(data);
    EXPECT_EQ(ret, true);

    MessageParcel reply;
    MediaAlbumsControllerService controller;
    controller.DeletePhotoAlbums(data, reply);

    IPC::MediaRespVo<IPC::MediaEmptyObjVo> respVo;
    ret = respVo.Unmarshalling(reply);
    EXPECT_EQ(ret, true);

    auto deleteRows = respVo.GetErrCode();
    EXPECT_EQ(deleteRows, 5);

    MEDIA_INFO_LOG("DeleteAlbums_Test_002 end");
}
}  // namespace OHOS::Media