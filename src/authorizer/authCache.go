package authorize

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type AuthCache struct {
	DynamoDb  *dynamodb.Client
	TableName string
}

type AuthCacheValueEntity struct {
	PK          string
	SK          string
	Permissions []string
	Expiration  string
}

type AuthCacheValue struct {
	Permissions []string
	Expiration  time.Time
}

var cacheMap = make(map[string]AuthCacheValue)

var timestampLayout = "2006-01-02T15:04:05.0000000Z"

func (authCache *AuthCache) TryGet(authId string) (*AuthCacheValue, error) {
	val, ok := cacheMap[authId]
	if ok && val.Expiration.After(time.Now()) {
		return &val, nil
	}

	consistentRead := true
	keyVal, _ := attributevalue.Marshal(authId)

	response, err := authCache.DynamoDb.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName:      &authCache.TableName,
		ConsistentRead: &consistentRead,
		Key: map[string]types.AttributeValue{
			"PK": keyVal,
			"SK": keyVal,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve cache value with id %v: %v", authId, err.Error())
	}
	if response.Item == nil {
		return nil, nil
	}

	var authIdValue AuthCacheValue
	err = attributevalue.UnmarshalMap(response.Item, &authIdValue)
	if err != nil {
		return nil, fmt.Errorf("unable to parse response: %v", err)
	}

	return &authIdValue, nil
}

func (authIdCache *AuthCache) TryPut(authId string, value *AuthCacheValue) error {
	cacheMap[authId] = *value

	expiration := value.Expiration.UTC().Format(timestampLayout)

	valueEntity := AuthCacheValueEntity{
		PK:          authId,
		SK:          authId,
		Permissions: value.Permissions,
		Expiration:  expiration,
	}

	item, err := attributevalue.MarshalMap(valueEntity)
	if err != nil {
		return fmt.Errorf("unable to format authId cache value: %v", err)
	}

	_, err = authIdCache.DynamoDb.PutItem(context.TODO(), &dynamodb.PutItemInput{
		TableName: &authIdCache.TableName,
		Item:      item,
	})
	if err != nil {
		return fmt.Errorf("unable to store authId cache value: %v", err)
	}

	return nil
}
