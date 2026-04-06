/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef FAST_RESTORE_INIT_OPERAITON_H
#define FAST_RESTORE_INIT_OPERAITON_H
#include "rdb_helper.h"

namespace OHOS::Media {
class FastRestoreCallback : public NativeRdb::RdbOpenCallback {
public:
    virtual int32_t OnCreate(NativeRdb::RdbStore &rdb) override;
    virtual int32_t OnUpgrade(NativeRdb::RdbStore &rdb, int32_t oldVersion,
        int32_t newVersion) override;
};

class FastRestoreInitOperation {
public:
    static void InitRdbStore(std::shared_ptr<NativeRdb::RdbStore>& store, const std::string& path);
};
}
#endif // FAST_RESTORE_INIT_OPERAITON_H