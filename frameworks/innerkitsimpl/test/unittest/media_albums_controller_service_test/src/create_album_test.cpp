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

#define MLOG_TAG "MediaAlbumsControllerServiceTest"

#include "create_album_test.h"

#include <memory>
#include <string>

#define private public
#define protected public
#include "media_albums_controller_service.h"
#undef private
#undef protected

#include "create_album_vo.h"
#include "user_define_ipc_client.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unittest_utils.h"
#include "medialibrary_unistore_manager.h"

namespace OHOS::Media {
using namespace std;
using namespace testing::ext;
using namespace OHOS::NativeRdb;

static shared_ptr<MediaLibraryRdbStore> g_rdbStore;
static constexpr int32_t SLEEP_SECONDS = 1;

int32_t ClearUserAlbums()
{
    RdbPredicates predicates(PhotoAlbumColumns::TABLE);
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_TYPE, to_string(PhotoAlbumType::USER));

    int32_t rows = 0;
    int32_t err = g_rdbStore->Delete(rows, predicates);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to clear album table, err: %{public}d", err);
        return E_HAS_DB_ERROR;
    }
    return E_OK;
}

void CreateAlbumTest::SetUpTestCase(void)
{
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("Start MediaLibraryPhotoOperationsTest failed, can not get g_rdbStore");
        exit(1);
    }
    ClearUserAlbums();
    MEDIA_INFO_LOG("SetUpTestCase");
}

void CreateAlbumTest::TearDownTestCase(void)
{
    ClearUserAlbums();
    MEDIA_INFO_LOG("TearDownTestCase");
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_SECONDS));
}

void CreateAlbumTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
}

void CreateAlbumTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

bool CheckAlbum(int32_t albumId)
{
    int32_t count = 0;
    NativeRdb::RdbPredicates rdbPredicate(PhotoAlbumColumns::TABLE);
    rdbPredicate.EqualTo(PhotoAlbumColumns::ALBUM_ID, albumId);
    vector<string> columns = { PhotoAlbumColumns::ALBUM_ID };
    auto resultSet = MediaLibraryRdbStore::Query(rdbPredicate, columns);
    if (resultSet != nullptr) {
        resultSet->GetRowCount(count);
        resultSet->Close();
    }
    return count == 1;
}

int32_t ServiceCreateAlbum(const std::string &albumName)
{
    CreateAlbumReqBody reqBody;
    reqBody.albumName = albumName;

    MessageParcel data;
    if (reqBody.Marshalling(data) != true) {
        MEDIA_ERR_LOG("reqBody.Marshalling failed");
        return -1;
    }

    MessageParcel reply;
    auto service = make_shared<MediaAlbumsControllerService>();
    service->CreatePhotoAlbum(data, reply);

    IPC::MediaRespVo<IPC::MediaEmptyObjVo> respVo;
    if (respVo.Unmarshalling(reply) != true) {
        MEDIA_ERR_LOG("respVo.Unmarshalling failed");
        return -1;
    }

    return respVo.GetErrCode();
}

HWTEST_F(CreateAlbumTest, CreateAlbum_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CreateAlbum_Test_001");
    int32_t result = ServiceCreateAlbum("Album_Test_001.xxx");
    ASSERT_LT(result, 0);
}

HWTEST_F(CreateAlbumTest, CreateAlbum_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CreateAlbum_Test_002");
    int32_t result = ServiceCreateAlbum("Album_Test_002");
    ASSERT_GT(result, 0);
    bool hasAlbum = CheckAlbum(result);
    ASSERT_EQ(hasAlbum, true);
}
}  // namespace OHOS::Media