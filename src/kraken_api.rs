/*
  dmbcs-kraken-api-rust  Kraken API client library in Rust
  Copyright (C) 2022  Dale Mellor

  This program is free software: you can redistribute it and/or modify it under
  the terms of the GNU General Public License as published by the Free Software
  Foundation, either version 3 of the License, or (at your option) any later
  version.

  This program is distributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
  FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
  details.

  You should have received a copy of the GNU General Public License along with
  this program: it is in a file called LICENSE.txt.  If not, see
  <https://www.gnu.org/licenses/>.
*/



#![allow (non_snake_case,
          non_camel_case_types,
          non_upper_case_globals)]
#![warn (missing_docs)]


/*! An interface to the Kraken cryptocurrency exchange via its RESTful
    JSON-based API.

    It allows general exchange-wide data requests, and fully authenticated
    trading account-based requests.  The Kraken API is fully documented at
    <https://docs.kraken.com/rest>.

    Use this crate if you want to build custom automatons for algorithmic
    trading through this exchange, or if you want to provide an alternative
    interface to the one which the Kraken web site gives you.

    To use, call the [connect] method to obtain a handle object, maybe call
    [Kraken_API::set_opt] on the handle if you want to make a call to a Kraken
    end-point which accepts optional filter arguments, and then call the method
    on the handle which corresponds to the end-point you wish to invoke.  As
    this is a low-level library, the return will be a JSON string as sent by the
    exchange itself; you will need to be familiar with the Kraken API itself to
    interpret the returned data (and the intended use of the various
    end-points).

    Thus, an example program might appear as

    ```ignore
    use  DMBCS_KRAKEN_API  as  KKN;
    use  serde_json  as  JSN;

    fn  main  ()  ->  Result<(), String>   {

           let  mut  K  =  KKN::connect ("account key".to_string (),
                                         "secret".to_string ());

           K.set_opt (KKN::API_Option::START_TIME, "2022-01-01");

           let  json_result  =  K.account_balance () ?;

           let  json_result  =  JSN::from_str::<JSN::Value> (&json_result)
                                   .map_err (|E| E.to_string ()) ?;

           //  There should be code here to deal with the possibility that
           //  the exchange returned an error message to us.

           println! ("We currently have ${} in our account.",
                     json_result ["result"] ["ZUSD"].as_str ().ok_or ("0"));

           Ok (())
      }
    ```

    The 'account key' and the 'secret' should be obtained through the Kraken web
    service, and care must be taken to keep the secret secret (don't let it find
    its way into a public code repository!)

    Note that we made use of the `serde_json` crate to parse the response from
    the Kraken exchange, but this is absolutely not mandated by this library.

    ##  Limitations / To do

    * The user needs to be familiar with the Kraken documentation to be able to
      use this crate effectively.  While the crate does help with the formatting
      of calls and authentication and authorization information, it gives little
      help with interpreting the responses received from the exchange; as well
      as working knowledge of the Kraken protocols, an external JSON crate is
      almost certainly required to handle this.

    * We have currently implemented all of the *Market Data*, *User Data* and
      *User Trading* end-points.  The *User Funding* and *User Staking*
      end-points are not yet implemented, nor is the *Websockets
      Authentication* end-point.

    * Some specific strings which the exchange needs to see are not provided by
      the crate, and in particular the peculiarities of trading pairs like
      "ZUSDXBTC" have to be dealt with entirely by the user.  The exchange
      provides little consistency among these and coding for them is difficult
      and use-case specific.
*/



use  openssl  as  SSL;
use  std::collections::HashMap  as  Map;
use  std::sync::{Arc, Mutex};



/** Enumeration of available optional arguments which may be given to some of
    Kraken's API's end-points.  Note that the value given to the arguments will
    always be strings; the comments below indicate how the strings will be
    interpreted by the exchange.  */

#[derive(PartialEq,Eq,Hash)]
pub  enum  API_Option
{
    /** Information to be retrieved, one of "info", "leverage", "fees", or
        "margin".  */
    INFO = 0,

    /** Asset class; the only known valid value seems to be "currency". */
    ACLASS,

    /** An asset (e.g. "usd") about which to get information.  Can also be a
        comma-delimited list for some functions.  Can also be "all", which is
        the default when this optional argument is missing. */
    ASSET,

    /** Request to see trades (boolean as str); means slightly different things
        to different exchange end-points.  */
    TRADES,

    /** Restrict results to given user reference ID (i32 as str). */
    USERREF,

    /** Either a UNIX timestamp or transaction ID demarking the start of
        returned results. */
    START,

    /** Either a UNIX timestmap or transaction ID demarking the end of returned
        results. */
    END,

    /** Offset into full list of results, to effect pagination into the list. */
    OFS,

    /** One of "open", "close", or "both", to determine which time stamp to use
        for searching/filtering. */
    CLOSE_TIME,

    /** A boolean indicating whether to do profit and loss calculations. */
    DO_CALCS,

    /** A trading pair, such as "XETCXETH", or, for some functions, a
     * comma-separated list such as "XXBTCZUSD,XETHXXBT". */
    PAIR,

    /** A boolean value indicating whether or not to include fee info in the
        results. */
    FEE_INFO,

    /** A comma-delimited list of order flags: "post", "fcib", "fciq", "nompp".
        See the [upstream
        documentation](https://docs.kraken.com/rest/#operation/addOrder) for the
        [Kraken_API::add_order] end-point for details about the precise meanings
        of these terms. **/
    OFLAGS,

    /** UXIX timestamp of the start of a report.  */
    START_TIME,

    /** UNIX timestamp of the end of a report.  */
    END_TIME,

    /** One of "CSV" or "TSV".  */
    FORMAT,

    /** Comma-delimited list of fields to include in a report; see the
        documentation for the
        [AddExport](https://docs.kraken.com/rest/#operation/addExport) end-point
        for valid entries.  */
    FIELDS,

    /** Expiration time, either "+<N>" for a number of seconds from now, or just
        "N" for a UNIX timestamp. */
    EXPIRE_TIME,

    /** Boolean indicating that the order should be validated but not actually
        submitted. */
    VALIDATE,

    /** Date-time stamp (RFC3339) after which the new order request should be
        rejected. */
    DEADLINE,

    /** One of "market", "limit", "stop-loss", "take-profit", "stop-loss-limit",
        "take-profit-limit", or "settle-position". */
    ORDER_TYPE,

    /** One of "all", "any position", "closed position", "closing position", "no
        position", to describe the type of trades. */
    TYPE,

    /** One of "limit", "stop-loss", "take-profit", "stop-loss-limit", or
        "take-profit-limit".  */
    CLOSE_TYPE,

    /** Conditional close order [API_Option::PRICE]. */
    CLOSE_PRICE_1,

    /** Conditional close order [API_Option::PRICE_2]. */
    CLOSE_PRICE_2,

    /** Limit price for limit orders, trigger price for all other types. */
    PRICE,

    /** Limit price for "stop-loss-limit" and "take-profit-limit" orders.  */
    PRICE_2,

    /**  One of "index" or "last" to indicate which price signal triggers an
         order. */
    TRIGGER,

    /**  Amount of leverage desired. */
    LEVERAGE,

    /**  One of "GTC" ('good 'til cancelled'), "IOC" ('immediate or cancel'),
         or "GTD" ('good 'til date'). */
    TIME_IN_FORCE,

    /** Order quantity in terms of the base asset. */
    VOLUME,

    /** Time frame interval in minutes (i32 as str). */
    INTERVAL,

    /** Time interval in seconds (isize as str). */
    TIMEOUT,

    /** Return data points since the given UNIX timestamp (i32 as str). */
    SINCE,

    /** The maximum number of data to return.  */
    COUNT,

    /** Varies by function, but lists one or more transaction IDs, or sometimes
        user reference IDs. */
    TXID,

    /** For the get_open_positions function, carries a market or symbol pair
        over which to consolidate the open margin positions. */
    CONSOLIDATION,

    /** Comma-delimited list of ledger IDs. */
    ID,

    /** Use pending replace, before complete replace (bool as str).  */
    CANCEL_RESPONSE,

    #[doc(hidden)]
    REPORT,
    
    #[doc(hidden)]
    DESCRIPTION,
    
    #[doc(hidden)]
    __CEILING
}

use  API_Option  as  Opt;



/**  When submitting a trade instruction, are we buying or selling?  */
pub  enum  Instruction  {  /** We are buying. */
                           BUY,

                           /** We are selling.  */
                           SELL  }

impl  Instruction  {  /** Get the exact string Kraken needs to express this
                          option. */
                      pub  fn  as_kraken_string (&self)  ->  &'static str
                      {   match self
                          {   Instruction::BUY  =>  "buy",
                              Instruction::SELL =>  "sell" } } }



/**  When submitting a trade instruction, what order type do we want to make? */
pub  enum  Order_Type
{
    /** A market order: to be executed as soon as possible at whatever the
        market price happens to be.  */
    MARKET = 0,
    
    /** A limit order: to be executed when the price is below the limit when
        buying, or above the limit when selling. */
    LIMIT,

    /** A stop-loss order: to be executed when the price is above the order when
        buying, or below the order when selling. */
    STOP_LOSS,

    /** Execute the order when the price is below the order when buying, above
        the order when selling. */
    TAKE_PROFIT,

    /**  */
    STOP_LOSS_PROFIT,

    /**  */
    STOP_LOSS_PROFIT_LIMIT,

    /**  */
    STOP_LOSS_LIMIT,

    /**  */
    TAKE_PROFIT_LIMIT,

    /**  */
    TRAILING_STOP,

    /**  */
    TRAILING_STOP_LIMIT,

    /**  */
    STOP_LOSS_AND_LIMIT,

    /**  */
    SETTLE_POSITION
}

impl  Order_Type
{   /** Present the order type precisely as the Kraken API specifies. */
    pub fn as_kraken_string (&self)  ->  &'static str
    {   match self
        {   Order_Type::MARKET                 =>  "market",
            Order_Type::LIMIT                  =>  "limit",
            Order_Type::STOP_LOSS              =>  "stop-loss",
            Order_Type::TAKE_PROFIT            =>  "take-profit",
            Order_Type::STOP_LOSS_PROFIT       =>  "stop-loss-profit",
            Order_Type::STOP_LOSS_PROFIT_LIMIT =>  "stop-loss-profit-limit",
            Order_Type::STOP_LOSS_LIMIT        =>  "stop-loss-limit",
            Order_Type::TAKE_PROFIT_LIMIT      =>  "take-profit-limit",
            Order_Type::TRAILING_STOP          =>  "trailing-stop",
            Order_Type::TRAILING_STOP_LIMIT    =>  "trailing-stop-limit",
            Order_Type::STOP_LOSS_AND_LIMIT    =>  "stop-loss-and-limit",
            Order_Type::SETTLE_POSITION        =>  "settle-position" } } }




/** When exporting bulk data, we must specify the nature of the reporting
    format. */
pub  enum  Report_Type  {  /** Trades. */ TRADES,  /** Ledgers. */ LEDGERS  }

impl  Report_Type  {  fn  as_kraken_string (&self) -> &'static str
                      { match self { Report_Type::TRADES => "trades",
                                     Report_Type::LEDGERS => "ledgers" } } }



/** A handle on the connection to the Kraken exchange.

    This can be used multiple times, so should only be instantiated once,
    preferably using the [connect] function; due to the nature of the exchange
    and the REST API it does not make sense to make multiple requests in
    parallel, and so there should be no need for more than one of these objects
    to be instantiated.

    This object has a method implemented on it for every end-point in the Kraken
    API, which will make the call to the exchange as appropriate and marshall
    the returned data through the method's return object, described below.

    ## Optional arguments

    Many of the Kraken functions (end-points) can take optional extra arguments.
    These are set into the [Kraken_API] object prior to making a function call,
    and then those arguments which have been set and are pertinent to that
    function will be passed along.  The documentation for the individual
    functions below indicates the options pertinent to that function.

    The set of optional arguments persist between function calls: this may work
    in your favour or against you depending on your work flow.  In any case, use
    the methods [Kraken_API::set_opt], [Kraken_API::clear_opt] and
    [Kraken_API::clear_all_options] to manipulate the current option set.

    ## Errors

    Errors which occur at our end, such as failure to contact the Kraken
    exchange, or to perform our own processing, are signalled by returns of
    `Result::Err(String)` in which the string is a human-readable explanation of
    the problem.

    Errors which occur at the Kraken exchange, such as failure to authenticate
    the user, are signalled by an 'error' entry in the JSON string returned as a
    `Result::Ok(String)`.

    A successful return of data from the exchange will be seen with a 'result'
    section in the JSON string returned as `Result::Ok(String)`.  */

#[derive(Default)]
pub  struct  Kraken_API  {  key:        String,
                            secret:     String,
                            query_url:  String,
                            options:    Map<Opt, String>  }



const url_base: &str  =  "https://api.kraken.com/0";



/** Obtain a handle on a connection to the Kraken exchange.

    This function must be called before any other, and is the only way to get a
    Kraken_API handle on which all the access methods are usable; the
    [Kraken_API::default] method can be used if only public access methods of
    the Kraken exchange are to be used.

    The ‘key’ and ‘secret’ must have been obtained through the Kraken web site,
    and must be supplied here precisely as given.  However, note that this
    method cannot fail: no checks are performed at this point on the
    plausibility or actual validity of the credentials supplied.  */

pub  fn  connect  (key:  String,  secret:  String)  ->  Kraken_API
          {   Kraken_API { key,  secret,  ..Default::default ()  }   }



impl  Kraken_API
{
/********************  OPTIONAL ARGUMENT PROCESSING  **************************/


/** Give a value to the optional argument, which may be passed to the Kraken
    end-point if the end-point accepts this option. */

    pub  fn  set_opt<T: std::fmt::Display>
                                   (&mut  self,  opt:  API_Option,  value:  T)
          {   self.options.insert (opt, value.to_string ());   }



/** Clear an option; this will not be sent to any end-points which would accept
    such an optional argument. */

    pub  fn  clear_opt  (&mut  self,  opt: API_Option)
          {   self.options.remove (&opt);  }



/** The options set in a [Kraken_API] object are persistent across back-end
    calls; it may be prudent to call this method to make sure the set of options
    is in a well-known state, before making settings for the next back-end
    call.  */

    pub  fn  clear_all_options  (&mut  self)   {   self.options.clear ();   }




/***********************  USER DATA ENQUIRIES  ******************************/


/** Retrieve all cash balances.

    [Here](https://docs.kraken.com/rest/#operation/getAccountBalance) is the
    Kraken documentation.  */

  pub  fn  account_balance  (&mut self)  ->  Result<String, String>
    {  api_function (self, "Balance", &[], query_private)  }



/** Get a summary of standing with an asset.

    [Here](https://docs.kraken.com/rest/#operation/getTradeBalance) is the
    Kraken documentation.

    This function understands the [API_Option::ASSET] optional argument.  */

  pub  fn  trade_balance  (&mut self)  ->  Result<String, String>
    {  api_function (self, "TradeBalance", &[Opt::ASSET], query_private)  }



/** Get detailed information about currently open orders.

    The Kraken documentation is
    [here](https://docs.kraken.com/rest/#operation/getOpenOrders).

    The end-point is responsive to the [API_Option::TRADES] and
    [API_Option::USERREF] optional arguments.  */

  pub  fn  open_orders  (&mut self)  ->  Result<String, String>
    {  api_function
            (self, "OpenOrders", &[Opt::TRADES, Opt::USERREF], query_private)  }



/** Get a detailed list of closed orders, paged to up to 50 at a time.

    [Here](https://docs.kraken.com/rest/#operation/getClosedOrders) is the
    Kraken documentation.

    This function accepts [API_Option::TRADES], [API_Option::USERREF],
    [API_Option::START], [API_Option::END], [API_Option::OFS], and
    [API_Option::CLOSE_TIME] optional arguments.  */

  pub  fn  closed_orders  (&mut self)  ->  Result<String, String>
    {  api_function (self,
                    "ClosedOrders",
                    &[Opt::TRADES,  Opt::USERREF,  Opt::START,
                      Opt::END,     Opt::OFS,      Opt::CLOSE_TIME],
                    query_private)   }



/** Get a list of order details.

    This function is variously known in the [Kraken
    documentation](https://docs.kraken.com/rest/#operation/getOrdersInfo) as
    'Query Orders Info', 'GetOrdersInfo' and 'QueryOrders'.

    We see that 'txid' can be a comma-separated list of transaction identifiers,
    and that options [API_Option::TRADES] and [API_Option::USERREF] can
    optionally be set in the 'self' [Kraken_API] object prior to this call.  */

  pub  fn  query_orders  (&mut self, txid:  String)  ->  Result<String, String>
    {
      self.options.insert (Opt::TXID, txid);
      api_function (self,
                    "QueryOrders",
                    &[Opt::TXID, Opt::TRADES, Opt::USERREF],
                    query_private)
    }



/** Get a detailed list of past trades, paged to up to 50 at a time.

    The upstream documentation is
    [here](https://docs.kraken.com/rest/#operation/getTradeHistory).

    The function accepts [API_Option::TYPE], [API_Option::TRADES],
    [API_Option::START], [API_Option::END], and [API_Option::OFS] optional
    arguments.  */

  pub  fn  trades_history  (&mut self)  ->  Result<String, String>
    {  api_function  (self,
                      "TradesHistory",
                      &[Opt::TYPE, Opt::TRADES, Opt::START, Opt::END, Opt::OFS],
                      query_private)  }



/** Get information about specific trades.

    This function is known in the
    [Kraken documentation](https://docs.kraken.com/rest/#operation/getTradesInfo)
    as 'getTradesInfo', 'QueryTrades' and 'Query Trades Info'.

    We see that 'txid' can be a comma-separated list of transaction IDs, and the
    function accepts the [API_Option::TRADES] option, a string holding either
    "true" or "false".  */

  pub  fn  trades_info  (&mut self, txid:  String)  ->  Result<String, String>
    {
      self.options.insert (Opt::TXID, txid);
      api_function
               (self, "QueryTrades", &[Opt::TXID, Opt::TRADES], query_private)
    }



/** This function is for getting information about open *margin* positions.

    The end-point
    [documentation](https://docs.kraken.com/rest/#operation/getOpenPositions)
    is at Kraken, where it is known as 'getOpenPositions'.

    The method is sensitive to the optional arguments [API_Option::TXID],
    [API_Option::DO_CALCS] and [API_Option::CONSOLIDATION].  */

  pub  fn  open_margin_positions  (&mut self)  ->  Result<String, String>
    {  api_function  (self,
                      "OpenPositions",
                      &[Opt::TXID, Opt::DO_CALCS, Opt::CONSOLIDATION],
                      query_private)   }



/** Retrieve information about ledger entries.

    This end-point is known variously as "GetLedgersInfo", "getLedgers" and
    "Ledgers" in the
    [Kraken documentation](https://docs.kraken.com/rest/#operation/getLedgers).

    The function is sensitive to the [API_Option::ACLASS], [API_Option::ASSET],
    [API_Option::TYPE], [API_Option::START], [API_Option::END] and
    [API_Option::OFS] optional arguments.  */

  pub  fn  ledgers_info  (&mut self)  ->  Result<String, String>
    {  api_function (self,
                      "Ledgers",
                      &[Opt::ACLASS, Opt::ASSET, Opt::TYPE,
                        Opt::START,  Opt::END,   Opt::OFS],
                      query_private)   }



/** Retrieve information about specific ledger entries.

    [Here](https://docs.kraken.com/rest/#operation/getLedgersInfo)
    is the Kraken documentation.

    This is sensitive to the [API_Option::TRADES] and [API_Option::ID] optional
    arguments. */

  pub  fn  query_ledgers  (&mut self)  ->  Result<String, String>
    {  api_function
             (self, "QueryLedgers", &[Opt::ID, Opt::TRADES], query_private)  }


  
/** Get trade volue.

    Documented at
    [Kraken](https://docs.kraken.com/rest/#operation/getTradeVolume).

    The pair argument is the trading pair, e.g., "XETCXETH", for which data are
    required.

    The function also accepts the [API_Option::FEE_INFO] optional argument, to
    indicate that fee information should be included in the returned result
    set.  */

  /* !!!!  The handling of the pair argument is funny here, and we are doing it
           wrong.  */

  pub  fn  trade_volume  (&mut self, pair: &str)  ->  Result<String, String>
    {
       self.set_opt (Opt::PAIR, pair);
       api_function
            (self, "TradeVolume", &[Opt::PAIR, Opt::FEE_INFO], query_private)
    }



/** Request export of trades or ledgers.

    The upstream documentation is
    [here](https://docs.kraken.com/rest/#operation/addExport).

    Also uses the [API_Option::FORMAT], [API_Option::FIELDS],
    [API_Option::START_TIME] and [API_Option::END_TIME] optional arguments.  */

  pub  fn  request_export_report
                      (&mut self,  report_type: Report_Type,  description: &str)
               ->  Result<String, String>
    {
        self.set_opt (Opt::REPORT, report_type.as_kraken_string ());
        self.set_opt (Opt::DESCRIPTION,  description);
        api_function (self,
                      "AddExport",
                      &[Opt::REPORT, Opt::FORMAT,     Opt::DESCRIPTION,
                        Opt::FIELDS, Opt::START_TIME, Opt::END_TIME],
                      query_private)
    }



/** Get status of requested data exports.

    The Kraken documentation is
    [here](https://docs.kraken.com/rest/#operation/exportStatus).   */

  pub  fn  get_export_report_status  (&mut self,  report_type: Report_Type)
                ->  Result<String, String>
    {
        self.set_opt  (Opt::REPORT, report_type.as_kraken_string ());
        api_function  (self, "ExportStatus", &[Opt::REPORT], query_private)
    }



/** Retrieve a processed data export.

    The end-point documentation is
    [here](https://docs.kraken.com/rest/#operation/retrieveExport).  */

  pub  fn  retrieve_data_export  (&mut self,  id: &str)
                   ->  Result<String, String>
    {
        self.set_opt (Opt::ID,  id);
        api_function (self, "RetrieveExport", &[Opt::ID],  query_private)
    }
    


/** Delete an exported data report.

    [Here](https://docs.kraken.com/rest/#operation/removeExport) is the upstream
    documentation.

    NOTE that *type* MUST be one of the strings "delete" or "cancel", or a panic
    may occur.   */

    /* !!!!!  We must do better than this with the type argument. */

  pub  fn  delete_export_report  (&mut self,  id: &str,  type_: &str)
                    ->  Result<String, String>
    {
      assert! (type_ == "delete"  ||  type_ == "cancel");

      self.set_opt  (Opt::ID,  id);
      self.set_opt  (Opt::TYPE,  type_);
      api_function  (self, "RemoveExport", &[Opt::ID, Opt::TYPE], query_private)
    }




/**********************   USER TRADING   **************************************/



/** Place a new order onto the exchange's order book.

    The upstream documentation is
    [here](https://docs.kraken.com/rest/#operation/addOrder).
    
    The following optional arguments are considered by this end-point:
    [API_Option::USERREF], [API_Option::PRICE], [API_Option::PRICE_2],
    [API_Option::TRIGGER], [API_Option::LEVERAGE], [API_Option::OFLAGS],
    [API_Option::TIME_IN_FORCE], [API_Option::START_TIME],
    [API_Option::EXPIRE_TIME], [API_Option::CLOSE_TYPE],
    [API_Option::CLOSE_PRICE_1], [API_Option::CLOSE_PRICE_2],
    [API_Option::DEADLINE], and [API_Option::VALIDATE].  */

  pub  fn  add_order<V: std::fmt::Display>  (&mut self,
                                             order_type: Order_Type,
                                             direction: Instruction,
                                             volume:  V,
                                             pair:  &str)
               ->  Result<String, String>
    {
        self.set_opt (Opt::ORDER_TYPE, order_type.as_kraken_string ());
        self.set_opt (Opt::TYPE, direction.as_kraken_string ());
        self.set_opt (Opt::VOLUME, volume);
        self.set_opt (Opt::PAIR, pair);
        api_function  (self,
                       "AddOrder",
                       &[Opt::ORDER_TYPE,       Opt::TYPE,      Opt::VOLUME,
                         Opt::PAIR,             Opt::USERREF,   Opt::PRICE,
                         Opt::PRICE_2,          Opt::TRIGGER,   Opt::LEVERAGE,
                         Opt::OFLAGS,           Opt::TIME_IN_FORCE,
                         Opt::START_TIME,       Opt::EXPIRE_TIME,
                         Opt::CLOSE_TYPE,       Opt::CLOSE_PRICE_1,
                         Opt::CLOSE_PRICE_2,    Opt::DEADLINE,  Opt::VALIDATE],
                       query_private)
    }
                         


/** Edit an order on the exchange's order book.

    The upstream documentation is
    [here](https://docs.kraken.com/rest/#operation/editOrder).
    
    The following optional arguments are considered by this end-point:
    [API_Option::USERREF], [API_Option::PRICE], [API_Option::PRICE_2],
    [API_Option::OFLAGS], [API_Option::VOLUME], [API_Option::DEADLINE],
    [API_Option::CANCEL_RESPONSE], and [API_Option::VALIDATE].  */

  pub  fn  edit_order<V: std::fmt::Display>  (&mut self,
                                              tx_id: &str,
                                              pair:  &str)
               ->  Result<String, String>
    {
        self.set_opt (Opt::TXID, tx_id);
        self.set_opt (Opt::PAIR, pair);
        api_function  (self,
                       "AddOrder",
                       &[Opt::ORDER_TYPE,  Opt::VOLUME,
                         Opt::PAIR,        Opt::USERREF,   Opt::PRICE,
                         Opt::PRICE_2,     Opt::OFLAGS,
                         Opt::DEADLINE,    Opt::VALIDATE,
                         Opt::TXID,        Opt::CANCEL_RESPONSE],
                       query_private)
    }



/** Cancel an open order.

    The documentation for this end-point is at
    [Kraken](https://docs.kraken.com/rest/#operation/cancelOrder).  Note that
    'txid' can actually be a 'userref', in which case all open orders for that
    user are cancelled.  */
    
  pub  fn  cancel_order  (&mut self, txid:  &str)  ->  Result<String, String>
    {
      self.set_opt (Opt::TXID, txid);
      api_function (self, "CancelOrder", &[Opt::TXID], query_private)
    }



/** Cancel all orders open on this account.

    The documentation for this end-point is at
    [Kraken](https://docs.kraken.com/rest/#operation/cancelAllOrders).  */
    
  pub  fn  cancel_all_orders  (&mut self)  ->  Result<String, String>
    {
      api_function (self, "CancelAll", &[], query_private)
    }



/** Dead man's switch will cancel all orders after a time if not reset.

    The upstream documentation is
    [here](https://docs.kraken.com/rest/#operation/cancelAllOrdersAfter).  */

  pub  fn  cancel_all_orders_after_x  (&mut self,  timeout: isize)
               ->  Result<String, String>
    {
      self.set_opt (Opt::TIMEOUT,  timeout);
      api_function
              (self, "CancelAllOrdersAfter", &[Opt::TIMEOUT], query_private)
    }



/**********************   MARKET DATA   **************************************/

/** Get the server's time.
    Documented upstream
    [here](https://docs.kraken.com/rest/#tag/Market-Data). */

  pub  fn  server_time  (&mut self) ->  Result<String, String>
    {  api_function (self, "Time", &[], query_public)  }



      /* !!!!  We want to put a fully testable example of this function's use in
       *       here. */
/** Get the current exchange system status.

    Documented upstream
    [here](https://docs.kraken.com/rest/#operation/getSystemStatus).  */

  pub  fn  system_status  (&mut self) ->  Result<String, String>
    {  api_function (self, "SystemStatus", &[], query_public)  }




/** Get information about the assets that are available at this time at this
    exchange.

    The upstream documentation is
    [here](https://docs.kraken.com/rest/#operation/getAssetInfo).

    The function is responsive to the [API_Option::ACLASS] and
    [API_Option::ASSET] optional arguments.  */

  pub  fn  asset_info  (&mut self) ->  Result<String, String>
    {  api_function
         (self, "Assets", &[Opt::ACLASS, Opt::ASSET], query_public) }



/** Get tradable asset pairs.

    Documented at
    [Kraken](https://docs.kraken.com/rest/#operation/getTradableAssetPairs).

    The optional arguments [API_Option::INFO] and [API_Option::PAIR] will be
    used if set.  */

  pub  fn  asset_pairs  (&mut self) ->  Result<String, String>
    {  api_function (self, "AssetPairs", &[Opt::INFO, Opt::PAIR], query_public)}



/** Get ticker information.

    The upstream documentation is
    [here](https://docs.kraken.com/rest/#operation/getTickerInformation).  */

  pub  fn  ticker_info  (&mut self,  pair: String)  ->  Result<String, String>
    {  
      self.set_opt (Opt::PAIR, pair);
      api_function (self, "Ticker", &[Opt::PAIR], query_public)
    }



/** Get OLHC (open, low, high, close) data.

    The end-point is documented upstream
    [here](https://docs.kraken.com/rest/#operation/getOHLCData).

    The method respects the optional arguments [API_Option::INTERVAL] and
    [API_Option::SINCE].  */

  pub  fn  ohlc_data  (&mut self,  pair: String)  ->  Result<String, String>
    {
      self.set_opt (Opt::PAIR, pair);
      api_function
           (self, "OHLC", &[Opt::PAIR, Opt::INTERVAL, Opt::SINCE], query_public)
    }



/** Get live order book data.

    Upstream documentation is at
    [Kraken](https://docs.kraken.com/rest/#operation/getOrderBook).

    This end-point uses the optional argument [API_Option::COUNT] to limit the
    depth of data into the order book.  */

  pub  fn  order_book  (&mut self,  pair: String)  ->  Result<String, String>
    {
      self.set_opt (Opt::PAIR, pair);
      api_function (self, "Depth", &[Opt::PAIR, Opt::COUNT], query_public)
    }



/** Get recent trades made at the exchange.

    Documented
    [upstream](https://docs.kraken.com/rest/#operation/getRecentTrades).

    Allows the optional argument [API_Option::SINCE].  */

  pub  fn  recent_trades  (&mut self,  pair: String)  ->  Result<String, String>
    {
      self.set_opt (Opt::PAIR, pair);
      api_function (self, "Trades", &[Opt::PAIR, Opt::SINCE], query_public)
    }



/** Get recent spreads.

    Documented upstream
    [here](https://docs.kraken.com/rest/#operation/getRecentSpreads).

    Respects the optional argument [API_Option::SINCE].  */

  pub  fn  spread_data  (&mut self,  pair: String)  ->  Result<String, String>
    {
      self.set_opt (Opt::PAIR, pair);
      api_function (self, "Spread", &[Opt::PAIR, Opt::SINCE], query_public)
    }
}



fn  api_function  (K: &mut Kraken_API,
                   end_point: &str,
                   options: &[Opt],
                   do_query: fn(&Kraken_API)->Result<String,String>)
        ->  Result<String, String>
                {
                     K.query_url  =  end_point.to_string ();
                     query_add_options  (K,  options,  '?');
                     do_query (K)
                }



fn  query_public  (K:  &Kraken_API)  ->  Result<String, String>
{
    let  mut  C  =  curl::easy::Easy::new ();

    C.url (&(url_base.to_string () + "/public/" + &K.query_url)).unwrap ();

    let  query_result  =  Arc::new (Mutex::new (String::new ()));

    let  qr  =  query_result.clone ();
    C.write_function
            (move |data|
              {  *qr.lock ().unwrap () += std::str::from_utf8 (data).unwrap ();
                  Ok (data.len ())  })
        .map_err (|e| e.to_string ()) ?;

    C.perform ().map_err (|e| e.to_string ()) ?;

    let  x  =  Ok (query_result.lock ().unwrap ().to_string ());
    x
}



fn  query_private  (K:  &Kraken_API)  ->  Result<String, String>
{
    if  K.secret.len () != 88
        {   Err ("private key must be 88 characters long".to_string ()) ?   }

    let  nonce   =  std::time::SystemTime::now ()
                             .duration_since (std::time::UNIX_EPOCH) .unwrap ()
                             .as_micros ()
                             .to_string ();

    let  (query_url, post_data)  =  { let  mut  S  =  K.query_url.split ('?');
                                      (S.next ().unwrap ().to_string (),
                                       S.next ().unwrap_or ("").to_string ()) };

    let  post_data  =  &format! ("{}{}nonce={}",
                                 post_data,
                                 if post_data.is_empty () {""} else {"&"},
                                 nonce);

    let  mut  C  =  curl::easy::Easy::new ();

    C.url (&format! ("{}/private/{}", url_base, query_url)).unwrap ();

    C.post (true).unwrap ();
    C.post_fields_copy (post_data.as_bytes ()).unwrap ();

    C.http_headers
        ( {
             let  mut  L  =  curl::easy::List::new ();

             L.append (&format!("API-Key: {}", K.key)).unwrap ();

             let  key  =  SSL::pkey::PKey::hmac
                             (&SSL::base64::decode_block (&K.secret).unwrap ())
                           .unwrap ();

             let  mut  signer  =  SSL::sign::Signer::new
                                     (SSL::hash::MessageDigest::sha512 (), &key)
                                   .unwrap ();

             signer.update ("/0/private/".as_bytes ()).unwrap ();
             signer.update (query_url.as_bytes ()).unwrap ();
             signer.update (&SSL::hash::hash
                                         (SSL::hash::MessageDigest::sha256 (),
                                          (nonce + post_data).as_bytes ())
                               .unwrap ())
                   .unwrap ();

             L.append (&format!("API-Sign: {}",
                                &SSL::base64::encode_block
                                    (&signer.sign_to_vec ().unwrap ())))
              .unwrap ();

             L
        } ) .unwrap ();
    
    let  query_result  =  Arc::new  (Mutex::new (String::new ()));

    let  qr  =  query_result.clone ();
    C.write_function
            (move |data|
              {  *qr.lock ().unwrap () += std::str::from_utf8 (data).unwrap ();
                  Ok (data.len ())  })
     .unwrap ();

    C.perform ().map_err (|e| e.to_string ()) ?;

    let  x  =  Ok (query_result.lock ().unwrap ().to_string ());
    x
}



fn  kraken_argument  (O:  &Opt)  ->  &'static  str
{
    match  O  {   Opt::INFO             =>  "info",
                  Opt::ACLASS           =>  "aclass",
                  Opt::ASSET            =>  "asset",
                  Opt::TRADES           =>  "trades",
                  Opt::USERREF          =>  "userref",
                  Opt::START            =>  "start",
                  Opt::END              =>  "end",
                  Opt::OFS              =>  "ofs",
                  Opt::CLOSE_TIME       =>  "closetime",
                  Opt::DO_CALCS         =>  "docalcs",
                  Opt::PAIR             =>  "pair",
                  Opt::FEE_INFO         =>  "fee-info",
                  Opt::OFLAGS           =>  "oflags",
                  Opt::START_TIME       =>  "starttm",
                  Opt::END_TIME         =>  "endtm",
                  Opt::EXPIRE_TIME      =>  "expiretm",
                  Opt::FORMAT           =>  "format",
                  Opt::FIELDS           =>  "fields",
                  Opt::VALIDATE         =>  "validate",
                  Opt::DEADLINE         =>  "deadline",
                  Opt::ORDER_TYPE       =>  "ordertype",
                  Opt::LEVERAGE         =>  "leverage",
                  Opt::TIME_IN_FORCE    =>  "timeinforce",
                  Opt::VOLUME           =>  "volume",
                  Opt::TYPE             =>  "type",
                  Opt::CLOSE_TYPE       =>  "close[ordertype]",
                  Opt::CLOSE_PRICE_1    =>  "close[price]",
                  Opt::CLOSE_PRICE_2    =>  "close[price2]",
                  Opt::PRICE            =>  "price",
                  Opt::PRICE_2          =>  "price2",
                  Opt::TRIGGER          =>  "trigger",
                  Opt::INTERVAL         =>  "interval",
                  Opt::TIMEOUT          =>  "timeout",
                  Opt::SINCE            =>  "since",
                  Opt::COUNT            =>  "count",
                  Opt::TXID             =>  "txid",
                  Opt::CONSOLIDATION    =>  "consolidation",
                  Opt::ID               =>  "id",
                  Opt::CANCEL_RESPONSE  =>  "cancel_response",
                  Opt::DESCRIPTION      =>  "description",
                  Opt::REPORT           =>  "report",
                  Opt::__CEILING        =>  ""    }
}



fn  query_add_options  (K: &mut Kraken_API,
                        permitted_options: &[Opt],
                        mut joiner: char)
{   for  o  in  permitted_options
    {   if let Some(K_O) = K.options.get (o)
        {   K.query_url += &(std::mem::replace (&mut joiner, '&').to_string ()
                             + kraken_argument (o) + "=" + K_O);   }  }  }



#[cfg(test)]
mod  test
  {  #[test]  fn  server_time ()  ->  Result <(), String>
     {
         use  serde_json  as JSN;

         let  v = JSN::from_str::<JSN::Value> (&super::Kraken_API::default ()
                                     .server_time () ?)
                              .map_err (|E| E.to_string ()) ?;

         let  res  =  v ["result"] ["rfc1123"].as_str ().ok_or ("") ?;

         assert! (res.len () > 0);

         Ok (())
     }  }
