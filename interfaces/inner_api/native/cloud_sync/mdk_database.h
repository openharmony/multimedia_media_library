/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#ifndef OHOS_MEDIA_CLOUD_SYNC_DATABASE_H
#define OHOS_MEDIA_CLOUD_SYNC_DATABASE_H

#include <functional>
#include <map>
#include <string>
#include <vector>
#include <mutex>
#include <shared_mutex>
#include <list>

#include "mdk_record.h"
#include "mdk_result.h"

#define EXPORT __attribute__ ((visibility ("default")))

namespace OHOS::Media::CloudSync {
struct MDKSchemaField {
    std::string name;             // 名称
    MDKRecordFieldType type;      // 数据类型
    bool primary;                 // 是否为云端主键
    bool nullable;                // 是否可为空
    bool sortable;                // 是否支持排序
    bool searchable;              // 是否支持搜索
    bool queryable;               // 是否支持查询
    MDKRecordFieldType listType;  // 当type为list时，listType表示list的类型
    std::string refRecordType;    // 当type或listType为Reference类型时，该字段表示被引用的RecordType
};

struct MDKSchemaRelation {
    std::string relationName;
    std::string recordType;
    std::map<std::string, std::string> refFields;  // 可选，源表字段和目标表字段映射关系
};

struct MDKSchemaNode {
    std::string recordType;  // 云端表名 kind
    std::string tableName;   // 本地表名
    std::map<std::string, MDKSchemaField> fields;
    std::vector<std::string> dupCheckFields;   // 端侧去重主键
    std::string sharedTableName;               // 本地分享表名（可选）
    std::vector<MDKSchemaRelation> relations;  // 关联关系
};

struct MDKOrderTable {
    std::string recordType;  // 云端表名 kind
    std::string tableName;   // 本地表名
};

struct MDKSchema {
    int64_t version;  // 应用使用的schema version
    std::map<std::string, MDKSchemaNode> recordTypes;
    std::string schemaData;                  // schema的原始json字符串
    std::vector<MDKOrderTable> orderTables;  // 与schema中顺序一致
};
}  // namespace OHOS::Media::CloudSync
#endif