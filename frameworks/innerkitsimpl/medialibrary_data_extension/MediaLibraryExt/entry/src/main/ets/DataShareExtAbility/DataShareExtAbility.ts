import Extension from '@ohos.application.DataShareExtensionAbility'

export default class DataShareExtAbility extends Extension {
    private rdbStore_;

    onCreate(want) {
        console.log('[ttt] [MediaDataShare] <<Provider>> DataShareExtAbility onCreate, want:' + want.abilityName);
    }

    getFileTypes(uri: string, mimeTypeFilter: string) {
        console.info('[ttt] [MediaDataShare] <<Provider>> [getFileTypes] enter');
    }

    insert(uri, value, callback) {
        console.info('[ttt] [MediaDataShare] <<Provider>> [insert] enter');
    }

    update(uri, value, predicates, callback) {
        console.info('[ttt] [MediaDataShare] <<Provider>> [update] enter');
    }

    delete(uri, predicates, callback) {
        console.info('[ttt] [MediaDataShare] <<Provider>> [delete] enter');
    }

    query(uri, columns, predicates, callback) {
        console.info('[ttt] [MediaDataShare] <<Provider>> [query] enter');
    }

    getType(uri: string) {
        console.info('[ttt] [MediaDataShare] <<Provider>> [getType] enter');
    }

    batchInsert(uri: string, valueBuckets, callback) {
        console.info('[ttt] [MediaDataShare] <<Provider>> [batchInsert] enter');
    }

    normalizeUri(uri: string) {
        console.info('[ttt] [MediaDataShare] <<Provider>> [normalizeUri] enter');
    }

    denormalizeUri(uri: string) {
        console.info('[ttt] [MediaDataShare] <<Provider>> [denormalizeUri] enter');
    }
};
