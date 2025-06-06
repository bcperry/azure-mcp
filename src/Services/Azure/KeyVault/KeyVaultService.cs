// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Azure.Security.KeyVault.Keys;
using AzureMcp.Options;
using AzureMcp.Services.Interfaces;
using Azure.ResourceManager.KeyVault;

namespace AzureMcp.Services.Azure.KeyVault;

public sealed class KeyVaultService(ISubscriptionService subscriptionService) : BaseAzureService, IKeyVaultService
{
    private readonly ISubscriptionService _subscriptionService = subscriptionService ?? throw new ArgumentNullException(nameof(subscriptionService));
    private async Task<KeyVaultResource> GetKeyVaultAsync(
        string subscriptionId,
        string vaultName,
        string? tenant = null,
        RetryPolicyOptions? retryPolicy = null)
    {
        ValidateRequiredParameters(subscriptionId, vaultName);

        var subscription = await _subscriptionService.GetSubscription(subscriptionId, tenant, retryPolicy);

        await foreach (var account in subscription.GetKeyVaultsAsync())
        {
            if (account.Data.Name == vaultName)
            {
                return account;
            }
        }
        throw new Exception($"Cosmos DB account '{vaultName}' not found in subscription '{subscriptionId}'");
    }

    public async Task<List<string>> ListKeys(
        string vaultUri,
        bool includeManagedKeys,
        string subscriptionId,
        string? tenantId = null,
        RetryPolicyOptions? retryPolicy = null)
    {
        ValidateRequiredParameters(vaultUri, subscriptionId);

        var credential = await GetCredential(tenantId);
        var client = new KeyClient(new Uri(vaultUri), credential);
        var keys = new List<string>();

        try
        {
            await foreach (var key in client.GetPropertiesOfKeysAsync().Where(x => x.Managed == includeManagedKeys))
            {
                keys.Add(key.Name);
            }
        }
        catch (Exception ex)
        {
            throw new Exception($"Error retrieving keys from vault {vaultUri}: {ex.Message}", ex);
        }

        return keys;
    }

    public async Task<KeyVaultKey> GetKey(
        string vaultUri,
        string keyName,
        string subscriptionId,
        string? tenantId = null,
        RetryPolicyOptions? retryPolicy = null)
    {
        ValidateRequiredParameters(vaultUri, subscriptionId);

        if (string.IsNullOrWhiteSpace(keyName))
        {
            throw new ArgumentException("Key name cannot be null or empty", nameof(keyName));
        }

        var credential = await GetCredential(tenantId);
        var client = new KeyClient(new Uri(vaultUri), credential);

        try
        {
            return await client.GetKeyAsync(keyName);
        }
        catch (Exception ex)
        {
            throw new Exception($"Error retrieving key '{keyName}' from vault {vaultUri}: {ex.Message}", ex);
        }
    }

    public async Task<KeyVaultKey> CreateKey(
        string vaultUri,
        string keyName,
        string keyType,
        string subscriptionId,
        string? tenantId = null,
        RetryPolicyOptions? retryPolicy = null)
    {
        ValidateRequiredParameters(vaultUri, subscriptionId);

        if (string.IsNullOrWhiteSpace(keyName))
        {
            throw new ArgumentException("Key name cannot be null or empty", nameof(keyName));
        }

        if (string.IsNullOrWhiteSpace(keyType))
        {
            throw new ArgumentException("Key type cannot be null or empty", nameof(keyType));
        }

        var type = new KeyType(keyType);
        var credential = await GetCredential(tenantId);
        var client = new KeyClient(new Uri(vaultUri), credential);

        try
        {
            return await client.CreateKeyAsync(keyName, type);
        }
        catch (Exception ex)
        {
            throw new Exception($"Error creating key '{keyName}' in vault {vaultUri}: {ex.Message}", ex);
        }
    }

    public async Task<string> GetVaultUri(
        string vaultName,
        string subscriptionId,
        string? tenantId = null,
        RetryPolicyOptions? retryPolicy = null)
    {
        ValidateRequiredParameters(vaultName, subscriptionId);

        var credential = await GetCredential(tenantId);
        var keyvaultResource = await GetKeyVaultAsync(subscriptionId, vaultName, tenantId, retryPolicy);
        return keyvaultResource.Data.Properties.VaultUri.ToString();
    }


}
