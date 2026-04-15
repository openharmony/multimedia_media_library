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

#ifndef MEDIA_LIBRARY_UPGRADE_MACROS_H
#define MEDIA_LIBRARY_UPGRADE_MACROS_H

#include "media_library_upgrade_task.h"
#include "media_library_sql_builder.h"
#include "media_library_upgrade_task_registry.h"
#include "media_library_upgrade_helper.h"
#include "value_object.h"
#include <memory>

/**
 * @brief 注册老同步升级任务
 *
 * 使用函数指针封装升级逻辑，避免为每个版本创建单独的类
 * 同步任务在主升级线程中执行
 *
 * @param version_enum 版本枚举值
 * @param module_name 模块名称
 * @param func 升级函数指针（签名：int32_t (*)(RdbStore&)）
 *
 */
#define REGISTER_SYNC_UPGRADE_TASK(version_enum, module_name, func) \
    namespace { \
        const bool g_sync_upgrade_task_##version_enum = []() { \
            auto upgradeFunc = [](NativeRdb::RdbStore& store) -> int32_t { return func(store); }; \
            UpgradeTask::Config config(version_enum, #version_enum, module_name, true, upgradeFunc); \
            auto task = std::make_shared<UpgradeTask>(config); \
            UpgradeTaskRegistry::GetInstance().RegisterTask(task); \
            return true; \
        }(); \
    }

/**
 * @brief 注册老异步升级任务
 *
 * 使用函数指针封装升级逻辑，避免为每个版本创建单独的类
 * 异步任务在后台线程中执行
 *
 * @param version_enum 版本枚举值
 * @param module_name 模块名称
 * @param func 升级函数指针（签名：int32_t (*)(RdbStore&)）
 *
 */
#define REGISTER_ASYNC_UPGRADE_TASK(version_enum, module_name, func) \
    namespace { \
        const bool g_async_upgrade_task_##version_enum = []() { \
            auto upgradeFunc = [](NativeRdb::RdbStore& store) -> int32_t { return func(store); }; \
            UpgradeTask::Config config(version_enum, #version_enum, module_name, false, upgradeFunc); \
            auto task = std::make_shared<UpgradeTask>(config); \
            UpgradeTaskRegistry::GetInstance().RegisterTask(task); \
            return true; \
        }(); \
    }

/**
 * @brief 注册module级同步升级任务
 *
 * 使用函数指针封装升级逻辑，避免为每个版本创建单独的类
 * 异步任务在后台线程中执行
 *
 * @param version_enum 版本枚举值
 * @param module_name 模块名称
 * @param func 升级函数指针（签名：std::vector<std::pair<int32_t, int32_t>> (*)(RdbStore&)）
 *
 */
#define REGISTER_SYNC_UPGRADE_MODULE_TASK(version_enum, module_name, func) \
    namespace { \
        const bool g_sync_upgrade_task_##version_enum = []() { \
            auto upgradeFunc = [](NativeRdb::RdbStore& store) -> std::vector<std::pair<int32_t, int32_t>>
                { return func(store); }; \
            UpgradeModuleTask::Config config(version_enum, #version_enum, module_name, true, upgradeFunc); \
            auto task = std::make_shared<UpgradeModuleTask>(config); \
            UpgradeTaskRegistry::GetInstance().RegisterTask(task); \
            return true; \
        }(); }


/**
 * @brief 注册module级异步升级任务
 *
 * 使用函数指针封装升级逻辑，避免为每个版本创建单独的类
 * 异步任务在后台线程中执行
 *
 * @param version_enum 版本枚举值
 * @param module_name 模块名称
 * @param func 升级函数指针（签名：std::vector<std::pair<int32_t, int32_t>> (*)(RdbStore&)）
 *
 */
#define REGISTER_ASYNC_UPGRADE_MODULE_TASK(version_enum, module_name, func) \
    namespace { \
        const bool g_async_upgrade_task_##version_enum = []() { \
            auto upgradeFunc = [](NativeRdb::RdbStore& store) -> std::vector<std::pair<int32_t, int32_t>> \
                { return func(store); }; \
            UpgradeModuleTask::Config config(version_enum, #version_enum, module_name, false, upgradeFunc); \
            auto task = std::make_shared<UpgradeModuleTask>(config); \
            UpgradeTaskRegistry::GetInstance().RegisterTask(task); \
            return true; \
        }(); }


#endif // MEDIA_LIBRARY_UPGRADE_MACROS_H