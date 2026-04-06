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

#ifndef MEDIA_LIBRARY_UPGRADE_HELPER_H
#define MEDIA_LIBRARY_UPGRADE_HELPER_H

#include "media_library_sql_builder.h"
#include "rdb_store.h"
#include "value_object.h"
#include <functional>
#include <chrono>
#include <thread>

namespace OHOS {
namespace Media {
/**
 * @brief 升级辅助类
 *
 */
class UpgradeHelper {
public:
    UpgradeHelper() = delete;
    ~UpgradeHelper() = delete;

    /**
     * @brief 执行 SQL 命令列表
     * @param commands SQL 命令列表
     * @param store 数据库存储对象
     * @return sql索引与错误码的容器
     */
    static std::vector<std::pair<int32_t, int32_t>> ExecuteCommands(
        const std::vector<std::shared_ptr<ISqlCommand>>& commands, NativeRdb::RdbStore& store,
        bool needSkip = false);

    /**
     * @brief 带重试机制的 SQL 执行
     * @param execSql SQL 执行函数
     * @return 错误码，E_OK 表示成功
     */
    static int32_t ExecSqlWithRetry(std::function<int32_t()> execSql);
};

} // namespace Media
} // namespace OHOS

#endif // MEDIA_LIBRARY_UPGRADE_HELPER_H