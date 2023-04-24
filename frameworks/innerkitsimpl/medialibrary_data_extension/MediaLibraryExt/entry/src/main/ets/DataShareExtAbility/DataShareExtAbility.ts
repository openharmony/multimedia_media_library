import Extension from '@ohos.application.DataShareExtensionAbility';

export default class DataShareExtAbility extends Extension {
  private rdbStore_;

  onCreate(want): void {
    console.log('[MediaDataShare] <<Provider>> DataShareExtAbility onCreate, want:' + want.abilityName);
  }

  getFileTypes(uri: string, mimeTypeFilter: string): void {
    console.info('[MediaDataShare] <<Provider>> [getFileTypes] enter');
  }

  insert(uri, value, callback): void {
    console.info('[MediaDataShare] <<Provider>> [insert] enter');
  }

  update(uri, value, predicates, callback): void {
    console.info('[MediaDataShare] <<Provider>> [update] enter');
  }

  delete(uri, predicates, callback): void {
    console.info('[MediaDataShare] <<Provider>> [delete] enter');
  }

  query(uri, columns, predicates, callback): void {
    console.info('[MediaDataShare] <<Provider>> [query] enter');
  }

  getType(uri: string): void {
    console.info('[MediaDataShare] <<Provider>> [getType] enter');
  }

  batchInsert(uri: string, valueBuckets, callback): void {
    console.info('[MediaDataShare] <<Provider>> [batchInsert] enter');
  }

  normalizeUri(uri: string): void {
    console.info('[MediaDataShare] <<Provider>> [normalizeUri] enter');
  }

  denormalizeUri(uri: string): void {
    console.info('[MediaDataShare] <<Provider>> [denormalizeUri] enter');
  }
};
