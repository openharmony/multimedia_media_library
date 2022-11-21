/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef MEDIATHUMBNAIL_TEST_CB_H
#define MEDIATHUMBNAIL_TEST_CB_H

#include "medialibrary_db_const.h"
#include "rdb_open_callback.h"

namespace OHOS {
namespace Media {
class FetchResultTestCB : public NativeRdb::RdbOpenCallback {
public:
    int OnCreate(NativeRdb::RdbStore &rdbStore)
    {
        return rdbStore.ExecuteSql(CREATE_MEDIA_TABLE);
    }

    int OnUpgrade(NativeRdb::RdbStore &rdbStore, int oldVersion, int newVersion)
    {
        return 0;
    }
};
} // namespace Media
} // namespace OHOS
#endif // MEDIATHUMBNAIL_TEST_CB_H
