/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIALIBRARY_RDB_TRANSACTION_H
#define OHOS_MEDIALIBRARY_RDB_TRANSACTION_H

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <mutex>

#include "rdb_store.h"

namespace OHOS::Media {
#define EXPORT __attribute__ ((visibility ("default")))
static constexpr int32_t SQLITE3_DATABASE_LOCKER = -5;
/**
 * This class is used for database transaction creation, commit, and rollback
 * The usage of class is as follows:
 *   1. initialize TransactionOperations object with a rdb instance
 *          (for example: TranscationOperations opt(rdb))
 *   2. After init opt, you need call Start() function to start transaction
 *          int32_t err = opt.Start();
 *          if err != E_OK, transaction init failed
 *   3. If you need to commit transaction, then use
 *          int32_t err = opt.Finish();
 *          if err != E_OK, transaction commit failed and auto rollback
 *   4. If TransactionOperations is destructed without successfully finish, it will be auto rollback
 */
class TransactionOperations {
public:
    EXPORT TransactionOperations(const std::shared_ptr<OHOS::NativeRdb::RdbStore> &rdbStore);
    EXPORT ~TransactionOperations();
    EXPORT int32_t Start();
    EXPORT void Finish();

private:
    int32_t BeginTransaction();
    int32_t TransactionCommit();
    int32_t TransactionRollback();

    std::shared_ptr<OHOS::NativeRdb::RdbStore> rdbStore_;
    bool isStart = false;
    bool isFinish = false;

    static std::mutex transactionMutex_;
    static std::condition_variable transactionCV_;
    static std::atomic<bool> isInTransaction_;
};
} // namespace OHOS::Media

#endif // OHOS_MEDIALIBRARY_RDB_TRANSACTION_H
