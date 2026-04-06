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

#ifndef MEDIA_LIBRARY_SQL_BUILDER_H
#define MEDIA_LIBRARY_SQL_BUILDER_H

#include "media_library_sql_command.h"
#include "value_object.h"
#include <memory>
#include <vector>

namespace OHOS {
namespace Media {

/**
 * @brief SQL构建器
 *
 * 用于构建复杂的 SQL 操作序列，支持参数化查询
 */
class SqlBuilder {
public:
    SqlBuilder() = default;
    ~SqlBuilder() = default;

    /**
     * @brief 添加原始 SQL 命令（无参数）
     * @param sql SQL 语句
     * @return 构建器引用
     */
    SqlBuilder& AddRawSql(const std::string& sql);

    /**
     * @brief 添加参数化 SQL 命令（支持占位符和参数）
     * @param sql SQL 语句（包含占位符）
     * @param args 参数列表
     * @return 构建器引用
     */
    SqlBuilder& AddParameterizedSql(const std::string& sql, const std::vector<NativeRdb::ValueObject>& args);

    /**
     * @brief 添加列
     * @param tableName 表名
     * @param columnName 列名
     * @param columnType 列类型
     * @return 构建器引用
     */
    SqlBuilder& AddColumn(const std::string& tableName,
                          const std::string& columnName,
                          const std::string& columnType);

    /**
     * @brief 删除列
     * @param tableName 表名
     * @param columnName 列名
     * @return 构建器引用
     */
    SqlBuilder& DropColumn(const std::string& tableName, const std::string& columnName);

    /**
     * @brief 创建索引
     * @param indexName 索引名
     * @param tableName 表名
     * @param columnName 列名
     * @return 构建器引用
     */
    SqlBuilder& CreateIndex(const std::string& indexName,
                            const std::string& tableName,
                            const std::string& columnName);

    /**
     * @brief 删除索引
     * @param indexName 索引名
     * @return 构建器引用
     */
    SqlBuilder& DropIndex(const std::string& indexName);

    /**
     * @brief 删除触发器
     * @param triggerName 触发器名
     * @return 构建器引用
     */
    SqlBuilder& DropTrigger(const std::string& triggerName);

    /**
     * @brief 删除表
     * @param tableName 表名
     * @return 构建器引用
     */
    SqlBuilder& DropTable(const std::string& tableName);

    /**
     * @brief 构建命令列表
     * @return 命令列表
     */
    std::vector<std::shared_ptr<ISqlCommand>> Build() const;

    /**
     * @brief 清空构建器
     */
    void Clear();

private:
    std::vector<std::shared_ptr<ISqlCommand>> commands_;
};

} // namespace Media
} // namespace OHOS

#endif // MEDIA_LIBRARY_SQL_BUILDER_H